//! Parity test for `restore_participation` against a Go-produced
//! partkey DB.
//!
//! The fixture under `tests/fixtures/partkey/small.sqlite` was
//! generated with:
//!
//! ```bash
//! (cd ../go-algorand && go build -o /tmp/algokey-go ./cmd/algokey)
//! /tmp/algokey-go part generate \
//!     --keyfile /tmp/partkey.sqlite \
//!     --first 1 --last 100 --dilution 10 \
//!     --parent HNVCPPGOW2SC2YVDVDICU3YNONSTEFLXDXREHJR2YBEKDC2Z3IUZSC6YGI
//! cp /tmp/partkey.sqlite \
//!    crates/core/algo-ledger/tests/fixtures/partkey/small.sqlite
//! ```
//!
//! Expected field values (read from the Go-generated DB via
//! `algokey part info --keyfile <path>`):
//!
//! ```text
//! Parent address:           HNVCPPGOW2SC2YVDVDICU3YNONSTEFLXDXREHJR2YBEKDC2Z3IUZSC6YGI
//! VRF public key (b64):     ZZGfkAW3Aez9he8NSXK3VG99y05mZmK8RoJ8WQ+zd+k=
//! Voting public key (b64):  ygCFE+BjxNTnl2l3gLbbl4SBqp1Cqkc5dBZoUf9nPmI=
//! State proof key (b64):    waNZ0zpeKHIPcReils6xnVxYKPmMYXQ9Q8XMf5udh2MZUCmxT4DuS6zejH0IKksMiyZgXfyKv6BhPWZsWZ1/Ag==
//! State proof key lifetime: 256
//! First round:              1
//! Last round:               100
//! Key dilution:              10
//! ```
//!
//! `StateProofKeys` is empty in this fixture because no
//! `n * key_lifetime` round falls in `[1, 100]` (lifetime = 256).

use std::path::PathBuf;

use algo_ledger::erasable_db::ErasableDb;
use algo_ledger::participation::restore_participation;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/partkey/small.sqlite")
}

#[test]
fn restores_parent_and_round_metadata_from_go_db() {
    let db = ErasableDb::open_read_only(fixture_path()).expect("open partkey DB");
    let p = restore_participation(&db).expect("restore");
    // Parent address is the well-known zero-seed test address.
    assert_eq!(
        p.parent.to_string(),
        "HNVCPPGOW2SC2YVDVDICU3YNONSTEFLXDXREHJR2YBEKDC2Z3IUZSC6YGI"
    );
    assert_eq!(p.first_valid.0, 1);
    assert_eq!(p.last_valid.0, 100);
    assert_eq!(p.key_dilution, 10);
}

#[test]
fn vrf_pubkey_matches_go_output() {
    let db = ErasableDb::open_read_only(fixture_path()).expect("open");
    let p = restore_participation(&db).expect("restore");
    // Go reported `ZZGfkAW3Aez9he8NSXK3VG99y05mZmK8RoJ8WQ+zd+k=`.
    use data_encoding::BASE64;
    let want = BASE64
        .decode(b"ZZGfkAW3Aez9he8NSXK3VG99y05mZmK8RoJ8WQ+zd+k=")
        .unwrap();
    assert_eq!(
        p.vrf.pk.0.to_vec(),
        want,
        "VRF pubkey diverges from Go output"
    );
}

#[test]
fn state_proof_secrets_present_with_correct_key_lifetime() {
    let db = ErasableDb::open_read_only(fixture_path()).expect("open");
    let p = restore_participation(&db).expect("restore");
    let sp = p
        .state_proof_secrets
        .as_ref()
        .expect("state-proof secrets must be present (Go ran with default lifetime=256)");
    assert_eq!(sp.signer_context.first_valid, 1);
    assert_eq!(sp.signer_context.key_lifetime, 256);
    // StateProofKeys table is empty for this fixture (no n*256 round
    // falls in [1, 100]), so ephemeral_keys should be empty too.
    assert!(
        sp.ephemeral_keys.is_empty(),
        "ephemeral_keys should be empty for [1, 100] with lifetime 256, got {}",
        sp.ephemeral_keys.len()
    );
}

#[test]
fn restore_errors_on_empty_db() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.sqlite");
    // Create an empty erasable DB with the schema but no rows.
    {
        let db = ErasableDb::open(&path).unwrap();
        db.conn()
            .execute_batch(
                "CREATE TABLE ParticipationAccount (
                    parent BLOB, vrf BLOB, voting BLOB,
                    firstValid INTEGER, lastValid INTEGER,
                    keyDilution INTEGER NOT NULL DEFAULT 0,
                    stateProof BLOB
                );",
            )
            .unwrap();
        db.close().unwrap();
    }
    let db = ErasableDb::open_read_only(&path).unwrap();
    match restore_participation(&db) {
        Err(algo_ledger::participation::RestoreError::Empty) => {}
        Err(other) => panic!("expected Empty, got {other:?}"),
        Ok(_) => panic!("expected Empty error on row-less DB"),
    }
}
