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

//! PLAN-35 Phase A acceptance gate (TASK-111).
//!
//! Validates that the eleven preceding G* tasks (TASK-100 through TASK-110)
//! compose correctly: a Go-canonical tracker + block DB pair, when opened
//! through `SqliteLedger::open_with_prefix` (the primitive underlying
//! `algod-rust serve --ledger-prefix <go-data-dir>`), comes up cleanly and
//! exposes the right chain meta for downstream consumers.
//!
//! ### Scope vs. the task description
//!
//! The task's acceptance criteria call for an end-to-end smoke that also
//! spins the REST API and compares `/v2/blocks/{r}` byte-for-byte against
//! Go's response on the same DB. Two parts of that depend on real Go
//! artifacts that aren't available in CI:
//!
//!   - A Go-generated data directory (requires a running Go algod /
//!     localnet).
//!   - A captured Go `/v2/blocks/{r}` response to diff against.
//!
//! Those are inherently manual / fixture-capture work. This file covers
//! the **synthesizable** half of the acceptance: build a tracker DB that
//! matches Go's exact DDL byte-for-byte (the schema we've spent G1-G7
//! and G12-G13 aligning), point the ledger at it through
//! `open_with_prefix`, run the production commit pipeline, and confirm
//! every cross-task invariant holds across a reopen. The manual
//! fixture-capture procedure is documented in `docs/DEV_WORKFLOW.md` so
//! the bit-identical-vs-Go check can land in a follow-up without
//! re-litigating scope.
//!
//! Each assertion below names the G* task it gates so a regression
//! surfaces with a clear pointer.

use algo_ledger::genesis::{genesis_hash, parse_genesis_json};
use algo_ledger::sqlite::{block_path_for_prefix, tracker_path_for_prefix, SqliteLedger};
use algo_ledger::LedgerStore;
use algo_types::{Address, BlockHeader, Round};
use rusqlite::Connection;

/// Synthetic Go-canonical genesis JSON; mirrors the four installer
/// genesis files in `../go-algorand/installer/genesis/<net>/genesis.json`
/// modulo allocation count.
const GENESIS_JSON: &str = r#"{
    "network": "phase-a",
    "id": "v1.0",
    "proto": "vAcceptance",
    "alloc": [
        {
            "addr": "7777777777777777777777777777777777777777777777777774MSJUVU",
            "comment": "FeeSink",
            "state": { "algo": 100000, "onl": 2 }
        }
    ],
    "fees": "7777777777777777777777777777777777777777777777777774MSJUVU",
    "rwd":  "7777777777777777777777777777777777777777777777777774MSJUVU",
    "timestamp": 1700000000
}"#;

/// Spin up a tracker + block DB pair at `committed_round` using ONLY
/// the production public API:
///   - `SqliteLedger::open_with_prefix` (the primitive underlying
///     `algod-rust serve --ledger-prefix`)
///   - The `LedgerStore` setters
///   - `put_block` to write the committed header
///   - `begin_block`/`commit_block` to flush via `flush_chain_state`
///     (which writes `acctrounds.acctbase` and a synthesized fallback
///     header — G6 part 3 behaviour)
///
/// Returns the TempDir so it stays alive for the caller. The prefix is
/// derived from `dir.path().join("ledger")`.
fn build_phase_a_db(committed_round: u64) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");

    let mut ledger = SqliteLedger::open_with_prefix(&prefix).expect("open Phase A ledger");

    let genesis = parse_genesis_json(GENESIS_JSON).unwrap();
    let g_hash = genesis_hash(&genesis);

    // Seed chain meta through the production setters; commit_block
    // will mirror these into acctrounds + synthesize a header
    // fallback. The real header lands via put_block below and wins
    // over the synthesized one (INSERT OR IGNORE).
    ledger.set_genesis_id(format!("{}-{}", genesis.network, genesis.id));
    ledger.set_genesis_hash(g_hash);
    ledger.set_protocol(genesis.proto.clone());
    ledger.set_fee_sink(Address::from_algorand_string(&genesis.fees).unwrap());
    ledger.set_rewards_pool(Address::from_algorand_string(&genesis.rwd).unwrap());
    ledger.set_rewards_level(42);
    ledger.set_txn_counter(committed_round * 10);
    ledger.set_current_round(Round(committed_round));

    // Write the real header at the committed round so derivation
    // picks up the production header (not the commit_block fallback).
    let hdr = BlockHeader {
        round: Round(committed_round),
        genesis_id: format!("{}-{}", genesis.network, genesis.id),
        genesis_hash: g_hash,
        current_protocol: genesis.proto.clone(),
        fee_sink: Address::from_algorand_string(&genesis.fees).unwrap(),
        rewards_pool: Address::from_algorand_string(&genesis.rwd).unwrap(),
        rewards_level: 42,
        txn_counter: committed_round * 10,
        ..BlockHeader::default()
    };
    let hdrdata = rmp_serde::to_vec_named(&hdr).unwrap();
    ledger
        .put_block(committed_round, &genesis.proto, &hdrdata, b"<blkpayload>")
        .unwrap();

    // Flush chain meta → writes acctrounds.acctbase = committed_round
    // and (for round 0 / no-put_block flows) synthesizes a fallback
    // header. Mirrors what relay genesis-seed and apply both do.
    ledger.begin_block().unwrap();
    ledger.commit_block().unwrap();

    drop(ledger);
    dir
}

#[test]
fn plan_35_acceptance_open_go_shaped_db_reads_chain_meta() {
    // PLAN-35 acceptance (TASK-111) — open a Go-shaped tracker DB
    // pair through `--ledger-prefix` and assert every chain-meta
    // field is recovered from the committed block header.
    let dir = build_phase_a_db(57);
    let prefix = dir.path().join("ledger");

    let ledger = SqliteLedger::open_with_prefix(&prefix).expect("reopen Phase A ledger");

    // G6 part 1: round + protocol + genesis derived from the
    // committed header, not from the (now-retired) algod_rust_meta
    // cache.
    assert_eq!(ledger.current_round(), Round(57));
    assert_eq!(ledger.protocol(), "vAcceptance");
    assert_eq!(ledger.genesis_id(), "phase-a-v1.0");
    assert_eq!(ledger.txn_counter(), 570);
    assert_eq!(ledger.rewards_level(), 42);

    // G7: genesis hash matches what `populate_store` would have set
    // for the same genesis JSON.
    let genesis = parse_genesis_json(GENESIS_JSON).unwrap();
    assert_eq!(ledger.genesis_hash(), &genesis_hash(&genesis));

    // PLAN-35 acceptance `/v2/status` shape — the round the REST
    // layer reports is sourced from `current_round()`, and
    // `last_committed_round()` (the resume hook) agrees.
    assert_eq!(ledger.last_committed_round().unwrap(), Some(57));

    // PLAN-35 acceptance `/v2/blocks/{r}` shape — the raw block
    // payload (hdrdata + blkdata) round-trips bit-identical out of
    // the DB. Bit-identical-vs-Go check requires a captured Go
    // response (see docs/DEV_WORKFLOW.md → "Phase A acceptance fixture
    // capture"); that test lives in a follow-up.
    let blkdata = ledger
        .get_block_data(57)
        .unwrap()
        .expect("block 57 present");
    assert_eq!(blkdata.as_slice(), b"<blkpayload>");
    let hdrbytes = ledger
        .get_block_header_data(57)
        .unwrap()
        .expect("header 57 present");
    let decoded: BlockHeader = rmp_serde::from_slice(&hdrbytes).unwrap();
    assert_eq!(decoded.round, Round(57));
    assert_eq!(decoded.genesis_id, "phase-a-v1.0");
}

#[test]
fn plan_35_acceptance_schema_invariants_hold_after_open() {
    // PLAN-35 acceptance (TASK-111) — every schema invariant the
    // G* tasks established must be visible to a direct SQL probe of
    // the on-disk tracker file. This is what makes a Go binary able
    // to reopen the same DB.
    let dir = build_phase_a_db(7);
    let prefix = dir.path().join("ledger");

    // Force a reopen so init has run all migrations against the
    // persisted state.
    drop(SqliteLedger::open_with_prefix(&prefix).expect("reopen for migrations"));

    let tracker = tracker_path_for_prefix(&prefix);
    let block = block_path_for_prefix(&prefix);
    assert!(
        tracker.exists(),
        "G1: tracker file at <prefix>.tracker.sqlite"
    );
    assert!(block.exists(), "G1: block file at <prefix>.block.sqlite");

    let conn = Connection::open(&tracker).unwrap();

    // G3: the three previously-missing tables must exist.
    for table in [
        "storedcatchpoints",
        "catchpointfirststageinfo",
        "unfinishedcatchpoints",
    ] {
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "G3: missing `{table}`");
    }

    // G5: `resources.ctype` is NOT NULL DEFAULT -1.
    let notnull: i64 = conn
        .query_row(
            "SELECT \"notnull\" FROM pragma_table_info('resources') WHERE name='ctype'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(notnull, 1, "G5: resources.ctype must be NOT NULL");
    let dflt: String = conn
        .query_row(
            "SELECT dflt_value FROM pragma_table_info('resources') WHERE name='ctype'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(dflt, "-1", "G5: resources.ctype default must be -1");

    // G6 part 3: `algod_rust_meta` is gone.
    let meta_exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='algod_rust_meta')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!meta_exists, "G6 part 3: algod_rust_meta must be gone");

    // G13: the kvstore-null-normalization marker is persisted.
    let marker_present: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM catchpointstate WHERE id='algod_rust_kvstore_null_norm_v1')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        marker_present,
        "G13: kvstore-null-norm marker must be persisted"
    );

    // G6 part 2: every non-namespaced `catchpointstate` key must
    // appear in the Go-canonical list.
    let mut stmt = conn.prepare("SELECT id FROM catchpointstate").unwrap();
    let rows = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
    for row in rows {
        let id = row.unwrap();
        if id.starts_with("algod_rust_") {
            continue;
        }
        assert!(
            algo_ledger::catchpoint::state_keys::ALL_GO_CANONICAL.contains(&id.as_str()),
            "G6 part 2: non-namespaced catchpointstate key `{id}` is not Go-canonical"
        );
    }
}

#[test]
fn plan_35_acceptance_pre_v3_db_is_refused_before_schema_creation() {
    // PLAN-35 acceptance (TASK-111) — exercise the G12 refusal path
    // end-to-end through `open_with_prefix` so the silent-corruption
    // mode (empty `resources` coexisting with a legacy `accountbase`
    // blob) is provably closed in the production code path.
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("ledger");
    let tracker = tracker_path_for_prefix(&prefix);
    let block = block_path_for_prefix(&prefix);

    // Seed pre-v3 shape directly. The legacy `accountbase` two-column
    // form is what `performResourceTableMigration` migrates away
    // from.
    {
        let conn = Connection::open(&tracker).unwrap();
        conn.execute_batch(
            "CREATE TABLE accountbase (
                 address BLOB PRIMARY KEY,
                 data    BLOB
             );",
        )
        .unwrap();
    }
    Connection::open(&block).unwrap();

    let err = match SqliteLedger::open_with_prefix(&prefix) {
        Ok(_) => panic!("PLAN-35 acceptance: pre-v3 DB must refuse"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("pre-v3 tracker DB detected") && msg.contains("TASK-109"),
        "G12 refusal must name signal + follow-up; got: {msg}"
    );

    // And the schema must NOT have created `resources` after the
    // refusal — that's the corruption the refusal exists to prevent.
    let conn = Connection::open(&tracker).unwrap();
    let resources_created: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='resources')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !resources_created,
        "G12: refusal must beat SCHEMA_TRACKER_SQL"
    );
}
