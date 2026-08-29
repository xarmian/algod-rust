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

//! Integration tests for the SQLite wallet driver primitives.
//!
//! Acceptance bar for TASK-202:
//! - DDL byte-equality vs the Go literal (extracted into
//!   `tests/fixtures/wallet_schema.sql` from `daemon/kmd/wallet/driver/sqlite.go:58–81`)
//! - Round-trip: create empty wallet DB, close, reopen, read metadata
//! - Filename helpers behave the same way as Go's regex usage
//! - Claimed-wallets registry prevents duplicates

use algo_kmd::{
    is_database_filename, name_id_to_path, sanitize_filename, ClaimedWallets, Error, WalletDb,
    SQLITE_WALLET_DRIVER_NAME, SQLITE_WALLET_DRIVER_VERSION, WALLET_SCHEMA,
};
use std::path::Path;
use tempfile::TempDir;

const GO_WALLET_SCHEMA: &str = include_str!("fixtures/wallet_schema.sql");

#[test]
fn schema_matches_go_byte_for_byte() {
    // The constant in the library and the fixture extracted from
    // ../go-algorand/daemon/kmd/wallet/driver/sqlite.go:58–81 must be
    // bytewise identical. If schema bytes ever diverge, this test trips
    // before any wallet operation runs against a mismatched schema.
    assert_eq!(
        WALLET_SCHEMA.as_bytes(),
        GO_WALLET_SCHEMA.as_bytes(),
        "WALLET_SCHEMA must equal Go's walletSchema byte-for-byte"
    );
    // Sanity bounds, in case either side gets accidentally truncated.
    assert!(WALLET_SCHEMA.contains("CREATE TABLE IF NOT EXISTS metadata"));
    assert!(WALLET_SCHEMA.contains("CREATE TABLE IF NOT EXISTS keys"));
    assert!(WALLET_SCHEMA.contains("CREATE TABLE IF NOT EXISTS msig_addrs"));
}

#[test]
fn create_close_reopen_round_trip() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("test-wallet.db");

    // Create + insert opaque metadata row.
    {
        let db = WalletDb::create(&path).expect("create");
        db.insert_metadata(
            b"wallet-id-1",
            b"My Wallet",
            b"\x01\x02",
            b"\x03\x04",
            b"\x05",
        )
        .expect("insert metadata");
    } // db dropped → connection closed

    // Reopen and read metadata back.
    let db = WalletDb::open(&path).expect("open");
    let meta = db.read_metadata().expect("read metadata");
    assert_eq!(meta.id, b"wallet-id-1");
    assert_eq!(meta.name, b"My Wallet");
    assert_eq!(meta.driver_name, SQLITE_WALLET_DRIVER_NAME);
    assert_eq!(meta.driver_version, SQLITE_WALLET_DRIVER_VERSION);
}

#[test]
fn create_rejects_existing_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("collides.db");
    std::fs::write(&path, b"not actually a wallet").unwrap();

    let err = WalletDb::create(&path).unwrap_err();
    assert!(
        matches!(err, Error::WalletExists(_)),
        "expected WalletExists, got {err:?}"
    );
}

#[test]
fn open_missing_returns_database_connect() {
    let dir = TempDir::new().unwrap();
    let err = WalletDb::open(dir.path().join("does-not-exist.db")).unwrap_err();
    assert!(matches!(err, Error::DatabaseConnect));
}

#[test]
fn metadata_unique_constraint_maps_to_key_exists() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("dup.db");
    let db = WalletDb::create(&path).unwrap();
    db.insert_metadata(b"id-1", b"name-1", b"", b"", b"")
        .unwrap();

    // Second row with same wallet_id must hit the UNIQUE constraint
    // (metadata.wallet_id is `TEXT NOT NULL UNIQUE`) and surface as
    // KeyExists, mirroring Go's errKeyExists path.
    let err = db
        .insert_metadata(b"id-1", b"different-name", b"", b"", b"")
        .unwrap_err();
    assert!(matches!(err, Error::KeyExists), "got {err:?}");
}

#[test]
fn read_metadata_rejects_wrong_driver_name() {
    // Hand-craft a DB whose metadata row has a different driver_name so
    // we exercise the WrongDriver branch in read_metadata. We use raw
    // rusqlite here because the public surface intentionally won't let
    // you write a non-"sqlite" driver_name.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("foreign.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(WALLET_SCHEMA).unwrap();
        conn.execute(
            "INSERT INTO metadata (driver_name, driver_version, wallet_id, wallet_name, \
             mep_encrypted, mdk_encrypted, max_key_idx_encrypted) \
             VALUES ('not-sqlite', 1, ?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![&b"id"[..], &b"name"[..], &b""[..], &b""[..], &b""[..]],
        )
        .unwrap();
    }
    let db = WalletDb::open(&path).unwrap();
    assert!(matches!(db.read_metadata(), Err(Error::WrongDriver)));
}

#[test]
fn read_metadata_rejects_wrong_driver_version() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("future.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(WALLET_SCHEMA).unwrap();
        conn.execute(
            "INSERT INTO metadata (driver_name, driver_version, wallet_id, wallet_name, \
             mep_encrypted, mdk_encrypted, max_key_idx_encrypted) \
             VALUES (?1, 99, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                SQLITE_WALLET_DRIVER_NAME,
                &b"id"[..],
                &b"name"[..],
                &b""[..],
                &b""[..],
                &b""[..]
            ],
        )
        .unwrap();
    }
    let db = WalletDb::open(&path).unwrap();
    assert!(matches!(db.read_metadata(), Err(Error::WrongDriverVersion)));
}

#[test]
fn sanitize_and_database_filename_table() {
    // Cross-check against the Go regexes — a small table that hits each
    // category of character (alpha, digit, underscore, dash, space,
    // punctuation, slash, non-ASCII).
    for (input, expected) in [
        (&b"abc"[..], &b"abc"[..]),
        (b"a b", b"ab"),
        (b"!alpha?beta!", b"alphabeta"),
        (b"/etc/passwd", b"etcpasswd"),
        (b"name with-mixed_chars", b"namewith-mixed_chars"),
        (b"\xff\xfe", b""),
    ] {
        assert_eq!(sanitize_filename(input), expected.to_vec());
    }

    for name in ["wallet.db", "x.db", "long.path.with.dots.db"] {
        assert!(is_database_filename(name));
    }
    for name in ["wallet", "wallet.db.bak", "", "wallet.dbx"] {
        assert!(!is_database_filename(name));
    }
}

#[test]
fn name_id_to_path_collapses_when_sanitized_equal() {
    let dir = Path::new("/wallets");
    // After sanitization both reduce to "abc"
    assert_eq!(
        name_id_to_path(dir, b"abc", b"abc"),
        Path::new("/wallets/abc.db")
    );
    // After sanitization name "a!b!c" → "abc" but id "abc" → "abc";
    // they're equal so collapse.
    assert_eq!(
        name_id_to_path(dir, b"a!b!c", b"abc"),
        Path::new("/wallets/abc.db")
    );
    // Sanitized strings differ → name.id.db
    assert_eq!(
        name_id_to_path(dir, b"alpha", b"id1"),
        Path::new("/wallets/alpha.id1.db")
    );
}

#[test]
fn with_transaction_acquires_exclusive_lock() {
    // Regression for Codex PR #349 round 1: with_transaction used to
    // run BEGIN DEFERRED, so two concurrent generate_key callers
    // could both observe the same max_key_idx before either wrote.
    // BEGIN EXCLUSIVE acquires the write lock immediately, so a
    // competing writer on a second connection must error with BUSY
    // until the transaction commits — matching Go's
    // _txlock=exclusive (sqlite.go:46).
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("excl.db");
    let primary = WalletDb::create(&path).unwrap();
    primary
        .insert_metadata(b"id", b"name", b"", b"", b"")
        .unwrap();

    // Open a second connection on the same file.
    let other = WalletDb::open(&path).unwrap();

    primary
        .with_transaction(|_db| {
            // While `primary` holds the exclusive lock, `other` must
            // be unable to start its own write (BEGIN EXCLUSIVE
            // returns SQLITE_BUSY).
            let busy = other.with_transaction(|_| Ok::<_, Error>(()));
            assert!(
                busy.is_err(),
                "second BEGIN EXCLUSIVE while another tx holds the write lock must fail"
            );
            Ok::<_, Error>(())
        })
        .unwrap();

    // After commit, the second connection can start a transaction.
    other.with_transaction(|_| Ok::<_, Error>(())).unwrap();
}

#[test]
fn claimed_wallets_thread_safety_smoke() {
    use std::sync::Arc;
    use std::thread;

    let cw = Arc::new(ClaimedWallets::new());
    let mut handles = Vec::new();
    for i in 0..16 {
        let cw = Arc::clone(&cw);
        handles.push(thread::spawn(move || {
            let name = format!("name-{i}");
            let id = format!("id-{i}");
            cw.claim(name.as_bytes(), id.as_bytes())
        }));
    }
    for h in handles {
        h.join().unwrap().unwrap();
    }

    // Now everyone tries to re-claim "name-0"; exactly zero succeed.
    let mut conflicts = 0;
    let mut handles = Vec::new();
    for _ in 0..8 {
        let cw = Arc::clone(&cw);
        handles.push(thread::spawn(move || cw.claim(b"name-0", b"id-fresh")));
    }
    for h in handles {
        if h.join().unwrap().is_err() {
            conflicts += 1;
        }
    }
    assert_eq!(conflicts, 8, "every duplicate-name claim must be rejected");
}
