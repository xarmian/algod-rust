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

//! End-to-end test: write a partkey DB with TASK-175's writer, read it back
//! with the existing Phase B reader, and assert per-field equality.
//!
//! The state-proof key-table writer is owned by TASK-176; here we exercise
//! the metadata path only (`ParticipationAccount.stateProof` BLOB on the
//! single row; `StateProofKeys` rows attached on read return an empty
//! ephemeral key vector when the table doesn't yet exist, which matches
//! the reader's `load_state_proof_keys` no-table case).

use std::path::PathBuf;

use algo_consensus_crypto::{OneTimeSignatureSecrets, VrfKeypair};
use algo_ledger::erasable_db::ErasableDb;
use algo_ledger::participation::{
    persist_new_parent, persist_participation, restore_participation, Participation,
};
use algo_types::{Address, Round};

fn tmp_db_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "algod-rust-partkey-{}-{}.sqlite",
        name,
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

fn make_participation(parent: Address) -> Participation {
    // Tiny, deterministic-ish participation: 2-batch OTS, fresh VRF, no
    // state-proof secrets (so we exercise the simple persist path
    // before TASK-176 wires up StateProofKeys writes).
    let vrf = VrfKeypair::from_seed([7u8; 32]);
    let voting = OneTimeSignatureSecrets::generate(0, 2);
    Participation {
        parent,
        vrf,
        voting,
        first_valid: Round(1),
        last_valid: Round(1000),
        key_dilution: 100,
        state_proof_secrets: None,
    }
}

#[test]
fn persist_then_restore_roundtrips_all_fields() {
    let path = tmp_db_path("roundtrip");
    let mut db = ErasableDb::open(&path).expect("open db");

    let parent = Address([0xab_u8; 32]);
    let part = make_participation(parent);
    persist_participation(&mut db, &part).expect("persist");

    // Reopen RO to mimic Go's `algokey part info` flow: close write
    // handle, reopen for read.
    drop(db);
    let db = ErasableDb::open_read_only(&path).expect("reopen ro");
    let restored = restore_participation(&db).expect("restore");

    assert_eq!(restored.parent, part.parent);
    assert_eq!(restored.first_valid, part.first_valid);
    assert_eq!(restored.last_valid, part.last_valid);
    assert_eq!(restored.key_dilution, part.key_dilution);
    assert_eq!(restored.vrf.pk.0, part.vrf.pk.0);
    assert_eq!(restored.vrf.sk.seed(), part.vrf.sk.seed());
    assert_eq!(restored.voting.verifier(), part.voting.verifier());

    drop(db);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn persist_new_parent_updates_only_the_parent_column() {
    let path = tmp_db_path("reparent");
    let mut db = ErasableDb::open(&path).expect("open db");

    let original_parent = Address([0x11_u8; 32]);
    let part = make_participation(original_parent);
    persist_participation(&mut db, &part).expect("persist");

    let new_parent = Address([0x99_u8; 32]);
    persist_new_parent(&mut db, new_parent).expect("reparent");

    drop(db);
    let db = ErasableDb::open_read_only(&path).expect("reopen ro");
    let restored = restore_participation(&db).expect("restore");

    // Parent must be the new address; everything else must be unchanged.
    assert_eq!(
        restored.parent, new_parent,
        "reparent must update parent column"
    );
    assert_eq!(restored.first_valid, part.first_valid);
    assert_eq!(restored.last_valid, part.last_valid);
    assert_eq!(restored.key_dilution, part.key_dilution);
    assert_eq!(restored.vrf.pk.0, part.vrf.pk.0);
    assert_eq!(restored.voting.verifier(), part.voting.verifier());

    drop(db);
    let _ = std::fs::remove_file(&path);
}
