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

//! The TLS and proxy failures of an `https:` algod (issue #2507): `goal
//! version` against TLS servers that present each kind of unfit certificate,
//! send a handshake alert or break the handshake, and through an
//! `HTTPS_PROXY` that refuses, answers a non-200 CONNECT, tunnels or breaks.
//!
//! `fixtures/tls_errors.jsonl` holds what go v5.0.5-stable's `goal` printed
//! (exit code, stdout, stderr) and what the proxy saw, for one fixed
//! sequence of rows. goal-rust must produce the same rows (a default test, no
//! go needed); a `MIXED_CLUSTER=1` run re-checks the file against a real go
//! `goal` (`GOAL_GO` names a prebuilt one), and `REGEN_TLS_ERRORS_FIXTURE=1`
//! rewrites it from go:
//!
//! ```bash
//! MIXED_CLUSTER=1 REGEN_TLS_ERRORS_FIXTURE=1 cargo test -p goal-rust \
//!   --test tls_errors_e2e tls_errors_fixture_matches_go_goal
//! ```
//!
//! The certificates are test fixtures (self-signed P-256, some valid for a
//! name or an address, some expired or not yet valid, one that is a CA, one
//! for `clientAuth` only); a row that needs one trusted names it in
//! `SSL_CERT_FILE`, which both go and the platform verifier read.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

const FIXTURE: &str = "tests/fixtures/tls_errors.jsonl";

// Test certificates (DER, base64) and their PKCS#8 keys, generated once.
const CERT_IP_MISMATCH: &str = "MIIBYTCCAQigAwIBAgIUeQuzAXjgpKsuJftCxSM9t7PSgAcwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJZ29hbC10ZXN0MCAXDTI1MDEwMTAwMDAwMFoYDzIxMjUwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlnb2FsLXRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQDRQUe/rgxP4swwa/0hzlNfjgLrhcy/kq5w7shEaAlb1sS591CNcWHNb/VgTPzByBk8f47/MoJjToaWZdDHPaeozYwNDAPBgNVHREECDAGhwR/AAACMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0EAwIDRwAwRAIgFHRN7cHXKKpwnf0ho52D6xCsvusjxN24HUSnms8FGUMCIHVs4Gk88RNMfCHg5bbDiE83sf+zR1X7GfKipJqf2VNp";
const KEY_IP_MISMATCH: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrBrMifFXTfNqOlOhcpmlw/WyGuWLLmOK9z12WKoBECShRANCAAQDRQUe/rgxP4swwa/0hzlNfjgLrhcy/kq5w7shEaAlb1sS591CNcWHNb/VgTPzByBk8f47/MoJjToaWZdDHPae";
const CERT_DNS_MISMATCH: &str = "MIIBezCCASCgAwIBAgIUQokQXV9YwM2zDPsmQtaqZ2YQZmkwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJZ29hbC10ZXN0MCAXDTI1MDEwMTAwMDAwMFoYDzIxMjUwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlnb2FsLXRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATfdX4eIrp0a6ASjLRUSGUhaRjLpWNl0FvkgD8GJtOx+jDPvvJX3g8k9pNn0FgoywNxSj2E3P5bfX3OEtm2ajndo04wTDAnBgNVHREEIDAeggtleGFtcGxlLmNvbYIPd3d3LmV4YW1wbGUuY29tMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0EAwIDSQAwRgIhAPRAGsqobLWz4BUk8oZDV+vS12EaWbByzBzwe/auAZsKAiEA17FfR/ZF0k20gVwlggOPtD9pNFp6LHwgm/9QMUhbmhs=";
const KEY_DNS_MISMATCH: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgKwsZL9xX8t24F9j0FifL3mCQJhJrUf07RkBv074vG2ahRANCAATfdX4eIrp0a6ASjLRUSGUhaRjLpWNl0FvkgD8GJtOx+jDPvvJX3g8k9pNn0FgoywNxSj2E3P5bfX3OEtm2ajnd";
const CERT_NO_NAMES: &str = "MIIBUDCB96ADAgECAhRNQJET1bAKlmjKbspSL0E7bPk31zAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlnb2FsLXRlc3QwIBcNMjUwMTAxMDAwMDAwWhgPMjEyNTAxMDEwMDAwMDBaMBQxEjAQBgNVBAMMCWdvYWwtdGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCTfkOuE/s4gT+Q6lb/UTQhndVSuddbqcvvU5f6a1XFicVC9cU7LRsdqzYG/71OdMbZ8CS8F38fSW2mpunhornCjJTAjMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0EAwIDSAAwRQIgTk+T8slTK1fZ4NEDQLQtJyeZyvoJkNcgnM8NQtADw2gCIQDrIqYXSvpFjk9pkbguJ6xO4LoD+ll12YLIptwMkrsaiw==";
const KEY_NO_NAMES: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/QTMFJnNXl4uLi9DGHXGG6BIz/c6qIb4GTbkXdSWc5ShRANCAAQk35DrhP7OIE/kOpW/1E0IZ3VUrnXW6nL71OX+mtVxYnFQvXFOy0bHas2Bv+9TnTG2fAkvBd/H0ltpqbp4aK5w";
const CERT_EXPIRED: &str = "MIIBXzCCAQagAwIBAgIUEm9HZNsOq3XVksj7Uiza+820ZY4wCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJZ29hbC10ZXN0MB4XDTE5MDEwMTAwMDAwMFoXDTIwMDEwMTAwMDAwMFowFDESMBAGA1UEAwwJZ29hbC10ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEezyuZjz5UAswJ0exvAfCjYCKXlEovynH83Dco/B2WpXSQgsHEF2Bh0Xni2UFhQXxMWjt0w3OfK6mJ8ImzCg3qM2MDQwDwYDVR0RBAgwBocEfwAAATAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAoGCCqGSM49BAMCA0cAMEQCIAyw9q17O8pLW9elI7w6wnoc1t19xyM6bbniR9Q6vYePAiBm6l+T12SGmUZ4oImPUUFg/dfETfopB60LwGXWkaVumQ==";
const KEY_EXPIRED: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPTJn4CkUYI2PXWxjsfHKFfuUZ8Tl/Y0HnOqhXEc0K3mhRANCAAQR7PK5mPPlQCzAnR7G8B8KNgIpeUSi/KcfzcNyj8HZaldJCCwcQXYGHReeLZQWFBfExaO3TDc58rqYnwibMKDe";
const CERT_NOT_YET: &str = "MIIBZDCCAQqgAwIBAgIUe7Ac2YJeFydAIMjG2htcLIXMlEcwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJZ29hbC10ZXN0MCIYDzIwOTkwMTAxMDAwMDAwWhgPMjEwMDAxMDEwMDAwMDBaMBQxEjAQBgNVBAMMCWdvYWwtdGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLcx9hvuZkIabHRdEC7I7IWYU+8lGUGWb9Rnphr4KUm7pTv0DZWdVnGk/W+G5yzSiwlfa8lOJZaMm5UdISuMkIajNjA0MA8GA1UdEQQIMAaHBH8AAAEwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDATAKBggqhkjOPQQDAgNIADBFAiAIFxe5uPcTxDh2jLzkCeYGc+wA/dUnpqwgg87zg8zA2wIhANA2o4h9x24Rtnt315aUClwfSBokgeF2gJDGhjcX7bla";
const KEY_NOT_YET: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggNmukSLS5nr9yoxW+n7e/U0DYfiQ4FLrQL7hTAihLg6hRANCAAS3MfYb7mZCGmx0XRAuyOyFmFPvJRlBlm/UZ6Ya+ClJu6U79A2VnVZxpP1vhucs0osJX2vJTiWWjJuVHSErjJCG";
const CERT_GOOD: &str = "MIIBYTCCAQigAwIBAgIULoGTM9wZ9WlJlIcI1jxubn6buwYwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJZ29hbC10ZXN0MCAXDTI1MDEwMTAwMDAwMFoYDzIxMjUwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlnb2FsLXRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAToWa0lrfD2+uduN6VWn7vQI0CbFfEAepYwxIsmb37GJUA81tKB9RhvFcD0dGJd/7mlz7S/8MTFTg2YI7nxLfzRozYwNDAPBgNVHREECDAGhwR/AAABMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0EAwIDRwAwRAIgdN0f7C8OJffxXdJoFahK5kUMof+abscDDB5ZqGXx3QcCIEXkPKH6QzMn+yOJCSCT/Dla2EjEIchDKvvLuRhpSI2B";
const KEY_GOOD: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgEkyW3i3C6E7EHw8LvuFIuVxX2xQO83avVBjgrrvfOWmhRANCAAToWa0lrfD2+uduN6VWn7vQI0CbFfEAepYwxIsmb37GJUA81tKB9RhvFcD0dGJd/7mlz7S/8MTFTg2YI7nxLfzR";
const CERT_EKU_CLIENT: &str = "MIIBYjCCAQigAwIBAgIUY8aBg8cXPRmmcIMHWLA7fgBdLSswCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJZ29hbC10ZXN0MCAXDTI1MDEwMTAwMDAwMFoYDzIxMjUwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlnb2FsLXRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASk8eL4SP0NnqlDHTw8Q0OLpqmJmkuKfHHsstorXRMkFDxF7BX80dCAadpB09I0yYzzhOVs0wh+BXIN28XpH9fNozYwNDAPBgNVHREECDAGhwR/AAABMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwCgYIKoZIzj0EAwIDSAAwRQIgBj8RZj0QWn9HEbIOwg8rT/9MPcBf/p53mhk/8KYXdekCIQCEOjLsYR+VgaMJkcR66gkNcXiPrglWOUsTZKsAW662yA==";
const KEY_EKU_CLIENT: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjv/GHnU4fxPPcpCy5stn7zz4h6zpYF/vyKwhBEHIoh+hRANCAASk8eL4SP0NnqlDHTw8Q0OLpqmJmkuKfHHsstorXRMkFDxF7BX80dCAadpB09I0yYzzhOVs0wh+BXIN28XpH9fN";
const CERT_PROXIED: &str = "MIIBaDCCAQ6gAwIBAgIUN8284nJpYM7ZM8pahN+hmS4Ppb8wCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJZ29hbC10ZXN0MCAXDTI1MDEwMTAwMDAwMFoYDzIxMjUwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlnb2FsLXRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAThXebkd5Hik8VJbf3+XwznowvkhRE80oJrcGKTS9GmFHeiXPjLi914kVq2pZmzdsrNPAnd2fFHQB/geqZCZFXjozwwOjAVBgNVHREEDjAMggphbGdvZC50ZXN0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0EAwIDSAAwRQIhAOXRwFPC5pK8ZIB40a5FPt627UpFlpo/RQimxzOBielZAiAHA1Tbsbd3QBg/cyewx0k8SrTWY1eeYlF1eERqSROcYg==";
const KEY_PROXIED: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgIV5T1HPaztYbQWaeVcoum3uiYEz3TiAMj3/dzpMKp7ChRANCAAThXebkd5Hik8VJbf3+XwznowvkhRE80oJrcGKTS9GmFHeiXPjLi914kVq2pZmzdsrNPAnd2fFHQB/geqZCZFXj";

/// The answer of a TLS server that gets as far as an HTTP request.
const VERSIONS: &str = r#"{"versions":["v1"],"genesis_id":"tls-v1","genesis_hash_b64":"AA==","build":{"major":1,"minor":2,"build_number":3,"commit_hash":"abc","branch":"b","channel":"c"}}"#;

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

/// What the server of a row does.
#[derive(Clone, Copy)]
enum Server {
    /// A TLS server with this certificate, which answers `/versions`.
    Tls(&'static str, &'static str),
    /// Reads the ClientHello, writes a fatal alert record and closes.
    Alert(u8),
    /// Reads the ClientHello and closes the connection.
    CloseAfterHello,
    /// Reads the ClientHello, writes a record header of this length and
    /// some of its bytes, then closes.
    Record(u16, usize),
    /// Writes the bytes of a ServerHello-less handshake record and closes
    /// (a record that stops short).
    Truncated,
    /// Answers in plain HTTP at once.
    PlainHttp,
}

/// What the proxy of a row does after reading the CONNECT.
#[derive(Clone, Copy)]
enum Proxy {
    /// Nothing listens (port 1).
    Refused,
    /// Answers `HTTP/1.1 <code> <phrase>`.
    Status(u16, &'static str),
    /// Closes the connection.
    Close,
    /// Answers bytes that are not HTTP.
    Garbage,
    /// Answers 200 and relays to the row's server.
    Tunnel,
}

struct Row {
    name: &'static str,
    server: Option<Server>,
    proxy: Option<Proxy>,
    /// `algod.net` names this host (with the server's port) instead of
    /// `127.0.0.1`.
    host: Option<&'static str>,
    /// `SSL_CERT_FILE` holds this certificate.
    trust: Option<&'static str>,
    /// Environment variables; `{proxy}` is the proxy's address.
    env: Vec<(&'static str, &'static str)>,
}

fn row(name: &'static str) -> Row {
    Row {
        name,
        server: None,
        proxy: None,
        host: None,
        trust: None,
        env: Vec::new(),
    }
}

fn rows() -> Vec<Row> {
    let tls = |name: &'static str, cert: &'static str, key: &'static str| {
        let mut r = row(name);
        r.server = Some(Server::Tls(cert, key));
        r
    };
    let trusted = |name: &'static str, cert: &'static str, key: &'static str| {
        let mut r = tls(name, cert, key);
        r.trust = Some(cert);
        r
    };
    let mut v = Vec::new();
    // certificates nobody vouches for: go checks the validity period and the
    // name before it builds the chain
    v.push(tls("address mismatch", CERT_IP_MISMATCH, KEY_IP_MISMATCH));
    v.push(tls("name mismatch", CERT_DNS_MISMATCH, KEY_DNS_MISMATCH));
    v.push(tls("no names", CERT_NO_NAMES, KEY_NO_NAMES));
    v.push(tls("expired", CERT_EXPIRED, KEY_EXPIRED));
    v.push(tls("not yet valid", CERT_NOT_YET, KEY_NOT_YET));
    v.push(tls("unknown issuer", CERT_GOOD, KEY_GOOD));
    // the same certificates trusted
    v.push(trusted("trusted", CERT_GOOD, KEY_GOOD));
    v.push(trusted("trusted expired", CERT_EXPIRED, KEY_EXPIRED));
    v.push(trusted("trusted address mismatch", CERT_IP_MISMATCH, KEY_IP_MISMATCH));
    v.push(trusted("incompatible key usage", CERT_EKU_CLIENT, KEY_EKU_CLIENT));
    // handshake failures of the server's side
    for (name, code) in [
        ("alert handshake failure", 40u8),
        ("alert protocol version", 70),
        ("alert bad certificate", 42),
        ("alert unrecognized name", 112),
        ("alert internal error", 80),
        ("alert close notify", 0),
        ("alert unknown", 200),
        ("alert unknown CA", 48),
        ("alert no application protocol", 120),
        ("alert unexpected message", 10),
        ("alert record overflow", 22),
        ("alert certificate required", 116),
    ] {
        let mut r = row(name);
        r.server = Some(Server::Alert(code));
        v.push(r);
    }
    let mut r = row("closes after the hello");
    r.server = Some(Server::CloseAfterHello);
    v.push(r);
    let mut r = row("oversized record");
    r.server = Some(Server::Record(0xffff, 10));
    v.push(r);
    let mut r = row("record just over the limit");
    r.server = Some(Server::Record(18433, 10));
    v.push(r);
    let mut r = row("record that stops short");
    r.server = Some(Server::Record(100, 10));
    v.push(r);
    let mut r = row("truncated handshake record");
    r.server = Some(Server::Truncated);
    v.push(r);

    // HTTPS_PROXY
    let proxied = |name: &'static str, proxy: Proxy| {
        let mut r = row(name);
        r.host = Some("algod.test");
        r.proxy = Some(proxy);
        r.env = vec![("HTTPS_PROXY", "http://{proxy}")];
        r
    };
    v.push(proxied("proxy refused", Proxy::Refused));
    v.push(proxied("proxy 403", Proxy::Status(403, "Forbidden")));
    v.push(proxied("proxy 407", Proxy::Status(407, "Proxy Authentication Required")));
    v.push(proxied("proxy 502", Proxy::Status(502, "Bad Gateway")));
    v.push(proxied("proxy 403 without reason", Proxy::Status(403, "")));
    v.push(proxied("proxy closes", Proxy::Close));
    v.push(proxied("proxy garbage", Proxy::Garbage));
    let mut r = proxied("proxy tunnel", Proxy::Tunnel);
    r.server = Some(Server::Tls(CERT_PROXIED, KEY_PROXIED));
    r.trust = Some(CERT_PROXIED);
    v.push(r);
    let mut r = proxied("proxy tunnel unknown issuer", Proxy::Tunnel);
    r.server = Some(Server::Tls(CERT_PROXIED, KEY_PROXIED));
    v.push(r);
    for (name, cert, key) in [
        ("proxy tunnel name mismatch", CERT_DNS_MISMATCH, KEY_DNS_MISMATCH),
        ("proxy tunnel no names", CERT_NO_NAMES, KEY_NO_NAMES),
        ("proxy tunnel expired", CERT_EXPIRED, KEY_EXPIRED),
    ] {
        let mut r = proxied(name, Proxy::Tunnel);
        r.server = Some(Server::Tls(cert, key));
        r.trust = Some(cert);
        v.push(r);
    }
    let mut r = proxied("proxy tunnel to a closing server", Proxy::Tunnel);
    r.server = Some(Server::CloseAfterHello);
    v.push(r);
    let mut r = proxied("proxy tunnel to a plain HTTP server", Proxy::Tunnel);
    r.server = Some(Server::PlainHttp);
    v.push(r);
    let mut r = proxied("lower case https_proxy", Proxy::Status(403, "Forbidden"));
    r.env = vec![("https_proxy", "http://{proxy}")];
    v.push(r);
    let mut r = proxied("proxy with credentials", Proxy::Status(403, "Forbidden"));
    r.env = vec![("HTTPS_PROXY", "http://user:p%40ss@{proxy}")];
    v.push(r);
    let mut r = proxied("proxy without a scheme", Proxy::Status(403, "Forbidden"));
    r.env = vec![("HTTPS_PROXY", "{proxy}")];
    v.push(r);
    let mut r = proxied("proxy named by NO_PROXY", Proxy::Status(403, "Forbidden"));
    r.env.push(("NO_PROXY", "algod.test"));
    v.push(r);
    let mut r = proxied("HTTP_PROXY alone", Proxy::Status(403, "Forbidden"));
    r.env = vec![("HTTP_PROXY", "http://{proxy}")];
    v.push(r);
    let mut r = proxied("proxy for a loopback algod", Proxy::Status(403, "Forbidden"));
    r.host = None;
    r.server = Some(Server::Tls(CERT_GOOD, KEY_GOOD));
    v.push(r);
    let mut r = proxied("proxy with an unsupported scheme", Proxy::Status(403, "Forbidden"));
    r.env = vec![("HTTPS_PROXY", "ftp://{proxy}")];
    v.push(r);
    v
}

/// A rustls server for `cert` / `key`.
fn tls_config(cert: &str, key: &str) -> Arc<rustls::ServerConfig> {
    let decode = |s: &str| data_encoding::BASE64.decode(s.as_bytes()).unwrap();
    let cert = rustls::pki_types::CertificateDer::from(decode(cert));
    let key = rustls::pki_types::PrivateKeyDer::try_from(decode(key)).unwrap();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap(),
    )
}

/// Reads one TLS record (the ClientHello) from `stream`.
fn read_record(stream: &mut TcpStream) {
    let mut head = [0u8; 5];
    if stream.read_exact(&mut head).is_ok() {
        let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
        let mut body = vec![0u8; len];
        let _ = stream.read_exact(&mut body);
    }
}

/// Serve `server` on a fresh port until the test process exits.
fn spawn_server(server: Server) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let config = match server {
        Server::Tls(cert, key) => Some(tls_config(cert, key)),
        _ => None,
    };
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let config = config.clone();
            std::thread::spawn(move || match server {
                Server::Tls(..) => {
                    let mut conn = rustls::ServerConnection::new(config.unwrap()).unwrap();
                    while conn.is_handshaking() {
                        if conn.complete_io(&mut stream).is_err() {
                            return;
                        }
                    }
                    let mut tls = rustls::StreamOwned::new(conn, stream);
                    let mut req = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                        match tls.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => req.extend_from_slice(&buf[..n]),
                        }
                    }
                    let answer = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{VERSIONS}",
                        VERSIONS.len()
                    );
                    let _ = tls.write_all(answer.as_bytes());
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                }
                Server::Alert(code) => {
                    read_record(&mut stream);
                    let _ = stream.write_all(&[0x15, 3, 3, 0, 2, 2, code]);
                    std::thread::sleep(Duration::from_millis(200));
                }
                Server::CloseAfterHello => read_record(&mut stream),
                Server::Record(len, n) => {
                    read_record(&mut stream);
                    let [hi, lo] = len.to_be_bytes();
                    let mut bytes = vec![0x16, 3, 3, hi, lo];
                    bytes.extend(std::iter::repeat_n(0u8, n));
                    let _ = stream.write_all(&bytes);
                    std::thread::sleep(Duration::from_millis(200));
                }
                Server::Truncated => {
                    read_record(&mut stream);
                    let _ = stream.write_all(&[0x16, 3, 3, 0, 4, 2, 0]);
                    std::thread::sleep(Duration::from_millis(100));
                }
                Server::PlainHttp => {
                    let _ = stream.write_all(
                        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    std::thread::sleep(Duration::from_millis(200));
                }
            });
        }
    });
    port
}

/// Serve `proxy` on a fresh port; every CONNECT head it reads is appended to
/// `log`. `target` is the port a tunnel relays to.
fn spawn_proxy(proxy: Proxy, target: Option<u16>, log: Arc<Mutex<String>>) -> u16 {
    if matches!(proxy, Proxy::Refused) {
        return 1;
    }
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let log = log.clone();
            std::thread::spawn(move || {
                let mut head = Vec::new();
                let mut buf = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => head.push(buf[0]),
                    }
                }
                log.lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&head));
                match proxy {
                    Proxy::Refused | Proxy::Close => {}
                    Proxy::Status(code, phrase) => {
                        let line = if phrase.is_empty() {
                            format!("HTTP/1.1 {code}\r\n\r\n")
                        } else {
                            format!("HTTP/1.1 {code} {phrase}\r\n\r\n")
                        };
                        let _ = stream.write_all(line.as_bytes());
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    Proxy::Garbage => {
                        let _ = stream.write_all(b"xyz\r\n\r\n");
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    Proxy::Tunnel => {
                        let _ = stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
                        let Some(target) = target else { return };
                        let Ok(upstream) = TcpStream::connect(("127.0.0.1", target)) else {
                            return;
                        };
                        let mut from_client = stream.try_clone().unwrap();
                        let mut from_upstream = upstream.try_clone().unwrap();
                        let mut upstream = upstream;
                        let t = std::thread::spawn(move || {
                            let _ = std::io::copy(&mut from_client, &mut upstream);
                        });
                        let _ = std::io::copy(&mut from_upstream, &mut stream);
                        let _ = t.join();
                    }
                }
            });
        }
    });
    port
}

/// Every `127.0.0.1:<digits>` as `127.0.0.1:<P>`, and the current time of an
/// x509 validity error as `<NOW>`.
fn mask(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(i) = rest.find("127.0.0.1:") {
        let (head, tail) = rest.split_at(i + "127.0.0.1:".len());
        out.push_str(head);
        let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
        out.push_str("<P>");
        rest = &tail[digits..];
    }
    out.push_str(rest);
    let mut text = out;
    // the host's DNS server, which go's resolver names
    if let Some(i) = text.find("lookup ") {
        if let (Some(on), Some(end)) = (text[i..].find(" on "), text[i..].find(": no such host")) {
            if on < end {
                text.replace_range(i + on + 4..i + end, "<DNS>");
            }
        }
    }
    if let Some(i) = text.find("current time ") {
        let start = i + "current time ".len();
        if let Some(len) = text[start..].find(" is ") {
            text.replace_range(start..start + len, "<NOW>");
        }
    }
    text
}

fn pem(b64: &str) -> String {
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

fn run_row(goal: &Path, r: &Row) -> serde_json::Value {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dd = tmp.path().canonicalize().unwrap();
    let server_port = r.server.map(spawn_server);
    let log = Arc::new(Mutex::new(String::new()));
    let proxy_port = r.proxy.map(|p| spawn_proxy(p, server_port, log.clone()));
    let net = match (r.host, server_port) {
        (Some(host), _) => format!("https://{host}:4443"),
        (None, Some(p)) => format!("https://127.0.0.1:{p}"),
        (None, None) => "https://127.0.0.1:1".to_string(),
    };
    std::fs::write(dd.join("algod.net"), format!("{net}\n")).unwrap();
    std::fs::write(dd.join("algod.token"), "a".repeat(64)).unwrap();
    let mut cmd = Command::new(goal);
    cmd.arg("-d")
        .arg(&dd)
        .arg("version")
        .current_dir(&dd)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TZ", "UTC");
    if let Some(cert) = r.trust {
        let file = dd.join("trusted.pem");
        std::fs::write(&file, pem(cert)).unwrap();
        cmd.env("SSL_CERT_FILE", &file);
    }
    for (k, v) in &r.env {
        let proxy = format!("127.0.0.1:{}", proxy_port.unwrap_or(1));
        cmd.env(k, v.replace("{proxy}", &proxy));
    }
    let out = cmd.output().expect("run goal");
    std::thread::sleep(Duration::from_millis(50));
    let saw = log.lock().unwrap().clone();
    serde_json::json!({
        "name": r.name,
        "code": out.status.code(),
        "stdout": mask(&String::from_utf8_lossy(&out.stdout)),
        "stderr": mask(&String::from_utf8_lossy(&out.stderr)),
        "proxy_saw": mask(&saw),
    })
}

fn sequence(goal: &Path) -> Vec<serde_json::Value> {
    rows().iter().map(|r| run_row(goal, r)).collect()
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
fn tls_errors_fixture_matches_goal_rust() {
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
fn tls_errors_fixture_matches_go_goal() {
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
    if std::env::var("REGEN_TLS_ERRORS_FIXTURE").is_ok_and(|v| !v.is_empty() && v != "0") {
        std::fs::write(&path, text).expect("write the fixture");
        return;
    }
    let committed = std::fs::read_to_string(&path).expect("fixture file");
    assert!(
        committed == text,
        "{FIXTURE} differs from go's output: regenerate it with REGEN_TLS_ERRORS_FIXTURE=1"
    );
}
