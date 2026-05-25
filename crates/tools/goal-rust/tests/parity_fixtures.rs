//! Parity-harness sanity tests. Pin every committed fixture under
//! `tests/fixtures/parity/` to either:
//!
//! 1. The pure formatter that produces it (e.g. `make_status_string`
//!    for `node status`'s three branches), or
//! 2. A literal Go-template constant snapshot that's also embedded
//!    byte-exactly in `src/cmd/*.rs` and verified against running
//!    binaries by the per-leaf `tests/*_e2e.rs` files.
//!
//! Together with those per-leaf integration tests, this gives us a
//! cheap, deterministic, fast-feedback layer: any reword on the Go
//! side surfaces here as a fixture diff long before the e2e network
//! tests run.

#[path = "common/mod.rs"]
mod common;

use algo_rest_client::NodeStatus;
use goal_rust::cmd::node::make_status_string;

use common::assert_matches_fixture;

#[test]
fn node_status_synced_matches_fixture() {
    let stat = NodeStatus {
        last_round: 42,
        time_since_last_round: 3_500_000_000,
        catchup_time: 0,
        last_version: "future".into(),
        next_version: "future".into(),
        next_version_round: 100,
        next_version_supported: true,
        stopped_at_unsupported_round: false,
        last_catchpoint: None,
        ..NodeStatus::default()
    };
    // make_status_string omits the trailing newline and the
    // Genesis ID / Genesis hash lines — those come from the
    // per-leaf wrapper in `cmd::node::get_status`. The fixture
    // pins the full final output of `goal node status`, so we
    // reconstitute the suffix here.
    let mut s = make_status_string(&stat);
    s.push('\n');
    s.push_str("Genesis ID: testnet-v1\n");
    s.push_str("Genesis hash: SGVsbG8gV29ybGQAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n");
    assert_matches_fixture("node_status_synced", &s);
}

#[test]
fn node_status_catchpoint_matches_fixture() {
    let stat = NodeStatus {
        last_round: 1234,
        catchup_time: 12_300_000_000,
        catchpoint: Some("1234#abc".into()),
        catchpoint_total_accounts: Some(100),
        catchpoint_processed_accounts: Some(50),
        catchpoint_verified_accounts: Some(40),
        catchpoint_total_kvs: Some(200),
        catchpoint_processed_kvs: Some(150),
        catchpoint_verified_kvs: Some(140),
        catchpoint_acquired_blocks: Some(10),
        catchpoint_total_blocks: Some(20),
        ..NodeStatus::default()
    };
    let mut s = make_status_string(&stat);
    s.push('\n');
    assert_matches_fixture("node_status_catchpoint", &s);
}

#[test]
fn node_status_upgrade_voting_matches_fixture() {
    let mut stat = NodeStatus {
        last_round: 42,
        time_since_last_round: 3_500_000_000,
        catchup_time: 0,
        last_version: "future".into(),
        next_version: "future".into(),
        next_version_round: 100,
        next_version_supported: true,
        ..NodeStatus::default()
    };
    stat.upgrade_next_protocol_vote_before = Some(1000);
    stat.upgrade_votes_required = Some(10000);
    stat.upgrade_yes_votes = Some(3000);
    stat.upgrade_no_votes = Some(500);
    stat.upgrade_vote_rounds = Some(10000);
    let mut s = make_status_string(&stat);
    s.push('\n');
    assert_matches_fixture("node_status_upgrade_voting", &s);
}

#[test]
fn node_lastround_matches_fixture() {
    // `lastround` prints `<round>\n`. Pure formatting.
    let s = "4096\n";
    assert_matches_fixture("node_lastround", s);
}

#[test]
fn wallet_new_created_matches_fixture() {
    let s = "Creating wallet...\nCreated wallet 'test-wallet'\n";
    assert_matches_fixture("wallet_new_created", s);
}

#[test]
fn wallet_list_empty_matches_fixture() {
    let s = "No wallets found. You can create a wallet with `goal wallet new`\n";
    assert_matches_fixture("wallet_list_empty", s);
}

#[test]
fn wallet_rename_ok_matches_fixture() {
    let s = "Renamed wallet 'foo' to 'bar'\n";
    assert_matches_fixture("wallet_rename_ok", s);
}
