//! End-to-end test for `fill_db_with_participation_keys`.
//!
//! Mirrors `../go-algorand/data/account/participation_test.go` ::
//! `TestParticipation_NewDB` and friends: drives the full orchestrator,
//! then re-reads via the Phase B reader, and asserts the participation
//! round-trips.

use std::path::PathBuf;

use algo_ledger::erasable_db::ErasableDb;
use algo_ledger::participation::{
    fill_db_with_participation_keys, restore_participation, FillError,
};
use algo_types::{Address, Round};

fn tmp_db_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "algod-rust-fill-{}-{}.sqlite",
        name,
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

#[test]
fn fill_small_window_persists_and_round_trips() {
    // Small range — keeps Falcon keygen runtime negligible.
    // first=1, last=KEY_LIFETIME_DEFAULT*2=512 → ~2 MSS keys.
    let path = tmp_db_path("small");
    let mut db = ErasableDb::open(&path).expect("open");

    let parent = Address([0x33; 32]);
    let part = fill_db_with_participation_keys(&mut db, parent, Round(1), Round(512), 100)
        .expect("fill must succeed");

    // The returned Participation must have the inputs reflected.
    assert_eq!(part.parent, parent);
    assert_eq!(part.first_valid, Round(1));
    assert_eq!(part.last_valid, Round(512));
    assert_eq!(part.key_dilution, 100);
    assert!(part.state_proof_secrets.is_some(), "MSS secrets generated");

    drop(db);

    // Re-read through the Phase B reader; every field must come back.
    let db = ErasableDb::open_read_only(&path).expect("reopen ro");
    let restored = restore_participation(&db).expect("restore");
    assert_eq!(restored.parent, parent);
    assert_eq!(restored.first_valid, Round(1));
    assert_eq!(restored.last_valid, Round(512));
    assert_eq!(restored.key_dilution, 100);
    assert_eq!(restored.vrf.pk.0, part.vrf.pk.0);
    assert_eq!(restored.voting.verifier(), part.voting.verifier());

    // State-proof secrets round-trip: commitment + key count match.
    let restored_sp = restored
        .state_proof_secrets
        .as_ref()
        .expect("restored MSS metadata");
    let original_sp = part.state_proof_secrets.as_ref().unwrap();
    assert_eq!(
        restored_sp.signer_context.first_valid,
        original_sp.signer_context.first_valid
    );
    assert_eq!(
        restored_sp.signer_context.key_lifetime,
        original_sp.signer_context.key_lifetime
    );
    assert_eq!(
        restored_sp.ephemeral_keys.len(),
        original_sp.ephemeral_keys.len(),
        "StateProofKeys row count round-trips"
    );

    drop(db);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fill_rejects_inverted_round_range_with_go_wording() {
    let path = tmp_db_path("inverted");
    let mut db = ErasableDb::open(&path).expect("open");
    let err =
        fill_db_with_participation_keys(&mut db, Address([0; 32]), Round(100), Round(50), 1000)
            .err()
            .expect("expected error");
    let msg = format!("{err}");
    assert!(
        msg.contains("firstValid 100 is after lastValid 50"),
        "actual: {msg}"
    );
    assert!(matches!(err, FillError::InvalidRange { .. }));

    drop(db);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fill_rejects_validity_period_exceeding_consensus_limit() {
    // V41's MaxKeyregValidPeriod = 256 * (1 << 16) - 1 = 16,777,215.
    let path = tmp_db_path("toolong");
    let mut db = ErasableDb::open(&path).expect("open");
    let err = fill_db_with_participation_keys(
        &mut db,
        Address([0; 32]),
        Round(1),
        Round(1 + 16_777_216), // one over the limit
        100,
    )
    .err()
    .expect("expected error");
    let msg = format!("{err}");
    assert!(
        msg.contains("the validity period for mss is too large"),
        "actual: {msg}"
    );
    // The reported limit must be V41's MaxKeyregValidPeriod (16,777,215),
    // proving the guard resolved the live consensus bound rather than the
    // zero default that would silently disable the check (BT-283).
    match err {
        FillError::ValidityPeriodTooLarge { limit } => {
            assert_eq!(limit, 256 * (1 << 16) - 1, "limit must be V41's bound");
        }
        other => panic!("expected ValidityPeriodTooLarge, got {other:?}"),
    }

    drop(db);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fill_defaults_key_dilution_when_zero() {
    // Passing 0 must trigger `default_key_dilution` (1 + floor(sqrt(window))).
    let path = tmp_db_path("dilution");
    let mut db = ErasableDb::open(&path).expect("open");
    let part = fill_db_with_participation_keys(
        &mut db,
        Address([0x44; 32]),
        Round(1),
        Round(101), // sqrt(100) = 10 → dilution = 11
        0,
    )
    .expect("fill");
    assert_eq!(part.key_dilution, 11, "default dilution = 1 + sqrt(100)");

    drop(db);
    let _ = std::fs::remove_file(&path);
}
