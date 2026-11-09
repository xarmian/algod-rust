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

//! Issue #2210 -- the archived rounds above the tracker round are replayed at
//! startup (go `trackerRegistry.loadFromDisk`, `ledger/tracker.go`).
//!
//! The crash test kills a real child process (`abort`, no cleanup) between the
//! block archive commit and the tracker commit of a real, applied block, then
//! reopens the files in this process and checks that `replay_archived_tail`
//! brings the tracker to the archive's tip without any peer, to exactly the
//! state of an uninterrupted run.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use algo_ledger::{replay_archived_tail, LedgerStore as _, SqliteLedger};
use algo_types::{Address, Block, Round};

const CHILD_ENV: &str = "ARCHIVE_REPLAY_CHILD_DIR";
const TARGET_ENV: &str = "ARCHIVE_REPLAY_TARGET";
const FAILPOINT_ENV: &str = "ARCHIVE_REPLAY_FAILPOINT";

/// A ledger whose rewards pool holds `MinBalance`, as every real genesis funds
/// it (go `StartEvaluator` withdraws block rewards from it); the funding is
/// committed before round 1, in the tracker only.
fn open_ledger(prefix: &Path) -> SqliteLedger {
    let mut ledger = SqliteLedger::open_with_prefix(prefix).unwrap();
    if ledger.last_committed_round().unwrap().is_none() {
        ledger.begin_block().unwrap();
        algo_ledger::apply::pool_fixtures::fund_test_rewards_pool(&mut ledger);
        ledger.commit_block().unwrap();
    }
    ledger
}

fn chain_block(round: u64) -> Block {
    Block {
        round: Round(round),
        fee_sink: Address([3u8; 32]),
        proposer: Address([9u8; 32]),
        current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
        ..Block::default()
    }
}

fn cert(round: u64) -> Vec<u8> {
    format!("certificate-{round}").into_bytes()
}

/// The archived form of a block: (header, block) msgpack.
fn encoded(block: &Block) -> (Vec<u8>, Vec<u8>) {
    (
        algo_codec::canonical_encode_block_header_from_block(block),
        algo_codec::encode_block(block).expect("encode block"),
    )
}

/// Commit a block as the follower does: archive rows and state change in one
/// block span (`AgreementLedgerBridge::try_commit_block`).
fn commit_round(ledger: &mut SqliteLedger, round: u64) {
    let block = chain_block(round);
    let (hdr, blk) = encoded(&block);
    ledger.begin_block().unwrap();
    ledger
        .put_block(round, &block.current_protocol, &hdr, &blk)
        .unwrap();
    ledger.put_block_cert(round, &cert(round)).unwrap();
    algo_ledger::apply::apply_block_executing_app_calls_for(ledger, &block, true).expect("apply");
    ledger.commit_block().unwrap();
}

/// Write only the archive rows of a round (sync writes blocks ahead of the
/// apply; a crash after the archive commit leaves the same rows).
fn archive_only(ledger: &mut SqliteLedger, block: &Block, cert_bytes: Option<&[u8]>) {
    let (hdr, blk) = encoded(block);
    ledger
        .put_block(block.round.0, &block.current_protocol, &hdr, &blk)
        .unwrap();
    if let Some(c) = cert_bytes {
        ledger.put_block_cert(block.round.0, c).unwrap();
    }
}

/// Child half of the crash test: commit rounds 1.. until the failpoint aborts
/// the process, reporting each round after its commit returned.
#[test]
fn archive_replay_child() {
    let Ok(dir) = std::env::var(CHILD_ENV) else {
        return;
    };
    let target: u64 = std::env::var(TARGET_ENV).unwrap().parse().unwrap();
    let mut ledger = open_ledger(&PathBuf::from(dir).join("ledger"));
    let (name, after) = std::env::var(FAILPOINT_ENV)
        .unwrap()
        .split_once(':')
        .map(|(n, a)| (n.to_string(), a.parse::<u64>().unwrap()))
        .unwrap();
    ledger.set_failpoint(&name, after);
    let stdout = std::io::stdout();
    for round in 1..=target {
        commit_round(&mut ledger, round);
        let mut out = stdout.lock();
        writeln!(out, "R {round}").unwrap();
        out.flush().unwrap();
    }
}

fn run_child_until_abort(dir: &Path, target: u64, failpoint: &str, after: u64) -> u64 {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "archive_replay_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, dir)
        .env(TARGET_ENV, target.to_string())
        .env(FAILPOINT_ENV, format!("{failpoint}:{after}"))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let reported = std::io::BufReader::new(stdout)
        .lines()
        .map_while(Result::ok)
        .filter_map(|l| l.strip_prefix("R ").and_then(|r| r.parse::<u64>().ok()))
        .max()
        .unwrap_or(0);
    assert!(
        !child.wait().unwrap().success(),
        "the failpoint did not fire"
    );
    reported
}

/// What an uninterrupted run holds after `last` rounds.
fn reference(last: u64) -> (u64, Round, Option<Vec<u8>>) {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = open_ledger(&dir.path().join("ledger"));
    for round in 1..=last {
        commit_round(&mut ledger, round);
    }
    (
        ledger.last_committed_round().unwrap().unwrap(),
        ledger.current_round(),
        ledger.get_block_header_data(last).unwrap(),
    )
}

/// The crash of the issue: the block archive is durable one block ahead of the
/// tracker. Reopened, the tracker is behind; the startup replay applies the
/// archived round from disk alone and lands on the uninterrupted state, and a
/// second replay (or the follower after it) has nothing left to do.
#[test]
fn a_crash_between_the_archive_and_the_tracker_commit_is_replayed_without_a_peer() {
    if std::env::var(CHILD_ENV).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    // The 3rd commit (after = 2) aborts after its archive commit.
    let reported = run_child_until_abort(dir.path(), 10, "after_archive_commit", 2);
    assert_eq!(reported, 2, "rounds 1 and 2 committed before the kill");

    let mut ledger = open_ledger(&dir.path().join("ledger"));
    assert_eq!(ledger.last_committed_round().unwrap(), Some(2));
    assert_eq!(
        ledger.max_block_round_in_blockdb().unwrap(),
        Some(3),
        "the archive is one block ahead of the tracker"
    );

    let report = replay_archived_tail(&mut ledger).unwrap();
    assert_eq!(report.from_round, 2);
    assert_eq!((report.applied, &report.stopped), (1, &None), "{report:?}");

    let (acct, current, header) = reference(3);
    assert_eq!(ledger.last_committed_round().unwrap(), Some(acct));
    assert_eq!(ledger.current_round(), current);
    assert_eq!(ledger.get_block_header_data(3).unwrap(), header);

    // Nothing left to replay, and the chain goes on from the archive's tip.
    assert_eq!(replay_archived_tail(&mut ledger).unwrap().applied, 0);
    commit_round(&mut ledger, 4);
    assert_eq!(ledger.last_committed_round().unwrap(), Some(4));
    drop(ledger);

    // And the replayed state survives a restart.
    let ledger = open_ledger(&dir.path().join("ledger"));
    assert_eq!(ledger.last_committed_round().unwrap(), Some(4));
}

/// A tail of several archived rounds (sync writes blocks ahead of the apply)
/// is replayed in order, up to the archive's tip.
#[test]
fn several_archived_rounds_above_the_tracker_are_all_replayed() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = open_ledger(&dir.path().join("ledger"));
    commit_round(&mut ledger, 1);
    for round in 2..=5 {
        archive_only(&mut ledger, &chain_block(round), Some(&cert(round)));
    }
    assert_eq!(ledger.last_committed_round().unwrap(), Some(1));

    let report = replay_archived_tail(&mut ledger).unwrap();
    assert_eq!((report.from_round, report.applied), (1, 4));
    assert_eq!(report.stopped, None);
    let (acct, current, header) = reference(5);
    assert_eq!(ledger.last_committed_round().unwrap(), Some(acct));
    assert_eq!(ledger.current_round(), current);
    assert_eq!(ledger.get_block_header_data(5).unwrap(), header);
}

/// A tracker at the archive's tip has nothing to replay.
#[test]
fn nothing_is_replayed_when_the_tracker_is_at_the_archive_tip() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = open_ledger(&dir.path().join("ledger"));
    for round in 1..=3 {
        commit_round(&mut ledger, round);
    }
    let report = replay_archived_tail(&mut ledger).unwrap();
    assert_eq!((report.from_round, report.applied), (3, 0));
    assert_eq!(report.stopped, None);
    // An empty ledger has nothing either.
    let dir = tempfile::tempdir().unwrap();
    let mut empty = open_ledger(&dir.path().join("ledger"));
    assert_eq!(replay_archived_tail(&mut empty).unwrap().applied, 0);
}

/// Failure is not fatal: a round without a certificate, or whose block does
/// not decode, stops the replay at the tracker's last good round; the rounds
/// before it stay applied and the ledger keeps working.
#[test]
fn a_round_that_cannot_be_replayed_stops_the_replay_without_failing_startup() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = open_ledger(&dir.path().join("ledger"));
    commit_round(&mut ledger, 1);
    archive_only(&mut ledger, &chain_block(2), Some(&cert(2)));
    // Round 3: no certificate yet.
    archive_only(&mut ledger, &chain_block(3), None);
    archive_only(&mut ledger, &chain_block(4), Some(&cert(4)));

    let report = replay_archived_tail(&mut ledger).unwrap();
    assert_eq!(report.applied, 1, "round 2 only");
    let (round, why) = report.stopped.expect("stopped at round 3");
    assert_eq!(round, 3);
    assert!(why.contains("certificate"), "{why}");
    assert_eq!(ledger.last_committed_round().unwrap(), Some(2));

    // Round 3's block is undecodable.
    ledger
        .put_block(3, "v41", b"hdr", b"not a msgpack block")
        .unwrap();
    ledger.put_block_cert(3, &cert(3)).unwrap();
    let report = replay_archived_tail(&mut ledger).unwrap();
    assert_eq!(report.applied, 0);
    let (round, why) = report.stopped.expect("stopped at round 3");
    assert_eq!(round, 3);
    assert!(why.contains("decode"), "{why}");
    assert_eq!(ledger.last_committed_round().unwrap(), Some(2));

    // The ledger is usable: the good block 3 arrives again (catchup) and the
    // replay then continues through round 4.
    archive_only(&mut ledger, &chain_block(3), Some(&cert(3)));
    let report = replay_archived_tail(&mut ledger).unwrap();
    assert_eq!((report.applied, report.stopped), (2, None));
    assert_eq!(ledger.last_committed_round().unwrap(), Some(4));
}
