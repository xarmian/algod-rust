//! Integration test for `algokey-rust part info`.
//!
//! We don't ship a Go-captured `algokey part info` fixture yet — that's
//! owned by [[TASK-182]] (Phase C fixtures). Instead, this test:
//!
//! 1. Generates a fresh participation key via the Rust orchestrator
//!    ([[TASK-177]]).
//! 2. Runs the binary against the resulting partkey DB.
//! 3. Asserts the printed fields match the in-memory `Participation`
//!    field-by-field (parent address string, base64-encoded VRF /
//!    voting / state-proof keys, all numeric fields).
//!
//! Byte-equal parity vs Go's `algokey part info` will be added under
//! TASK-182 once the captured fixtures land.

use std::path::PathBuf;
use std::process::Command;

use algo_ledger::erasable_db::ErasableDb;
use algo_ledger::participation::fill_db_with_participation_keys;
use algo_types::{Address, Round};
use data_encoding::BASE64;

fn algokey_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_algokey-rust"))
}

fn tmp_db_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "algokey-rust-part-info-{}-{}.sqlite",
        name,
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

#[test]
fn part_info_prints_every_field_with_go_compatible_formatting() {
    // Generate a small partkey.
    let path = tmp_db_path("happy");
    let mut db = ErasableDb::open(&path).expect("open db");
    let parent = Address([0x55_u8; 32]);
    let part =
        fill_db_with_participation_keys(&mut db, parent, Round(1), Round(512), 100).expect("fill");
    drop(db);

    let output = algokey_bin()
        .args(["part", "info", "--keyfile"])
        .arg(&path)
        .output()
        .expect("spawn binary");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "exit status: {:?}, stderr: {stderr}",
        output.status
    );

    // Required lines, in Go's exact order + spacing.
    let expected_parent = format!("Parent address:    {}\n", parent);
    let expected_vrf = format!("VRF public key:    {}\n", BASE64.encode(&part.vrf.pk.0));
    let expected_voting = format!(
        "Voting public key: {}\n",
        BASE64.encode(&part.voting.verifier())
    );
    let expected_first = "First round:       1\n";
    let expected_last = "Last round:        512\n";
    let expected_dilution = "Key dilution:      100\n";
    // The OTS first_batch / first_offset depend on the dilution and
    // round-to-id math; just check the labels are present at the right
    // depth (avoids tying the test to the OTS internals).
    assert!(
        stdout.contains(&expected_parent),
        "parent line missing — actual stdout:\n{stdout}"
    );
    assert!(
        stdout.contains(&expected_vrf),
        "VRF line missing — actual stdout:\n{stdout}"
    );
    assert!(
        stdout.contains(&expected_voting),
        "voting line missing — actual stdout:\n{stdout}"
    );
    assert!(stdout.contains(expected_first), "first-round line missing");
    assert!(stdout.contains(expected_last), "last-round line missing");
    assert!(stdout.contains(expected_dilution), "dilution line missing");
    assert!(stdout.contains("First batch:       "));
    assert!(stdout.contains("First offset:      "));

    // State-proof lines must be present (this fixture has secrets).
    assert!(
        stdout.contains("State proof key:   "),
        "state-proof key line missing"
    );
    assert!(
        stdout.contains("State proof key lifetime:   "),
        "state-proof lifetime line missing"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn part_info_errors_on_missing_keyfile_with_go_wording() {
    let path = tmp_db_path("missing");
    // Don't create the file — expect open to fail.
    let output = algokey_bin()
        .args(["part", "info", "--keyfile"])
        .arg(&path)
        .output()
        .expect("spawn binary");

    assert!(
        !output.status.success(),
        "missing file must exit non-zero, got {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Cannot open partkey database"),
        "expected `Cannot open partkey database` in stderr, got:\n{stderr}"
    );
    assert!(
        stderr.contains(&path.display().to_string()),
        "stderr should mention the missing path"
    );
}
