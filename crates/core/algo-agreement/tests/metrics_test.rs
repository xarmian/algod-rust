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

// Unit tests for the consensus-participation metrics (issue #473).
//
// Every assertion here drives `ParticipationMetrics` with the exact call
// sequence the agreement service makes for a round — Rezero (round start),
// Assemble (proposal), Attest (votes), Ensure (commit) — so the counters are
// verified against the real event ordering without a cluster, Docker, or any
// wall-clock sleeping (timings come from an injected `ManualMetricsClock`).

use std::sync::Arc;

use algo_agreement::metrics::{
    ManualMetricsClock, ParticipationMetrics, ParticipationSnapshot, RECENT_ROUND_CAPACITY,
};
use algo_agreement::{Period, Step, CERT, PROPOSE, SOFT};
use algo_types::{Digest, Round};

fn digest(b: u8) -> Digest {
    Digest([b; 32])
}

fn harness() -> (Arc<ParticipationMetrics>, Arc<ManualMetricsClock>) {
    let clock = Arc::new(ManualMetricsClock::new());
    let metrics = Arc::new(ParticipationMetrics::with_clock(clock.clone()));
    (metrics, clock)
}

/// Drive one complete round the way the service does.
fn run_round(
    m: &ParticipationMetrics,
    clock: &ManualMetricsClock,
    round: u64,
    own_digest: Option<Digest>,
    committed: Digest,
) {
    m.record_round_started(Round(round));
    clock.advance_ms(100);
    if let Some(d) = own_digest {
        m.record_proposal_made(Round(round), Period(0), &[d]);
    }
    clock.advance_ms(150);
    m.record_votes_cast(Round(round), Period(0), SOFT, 1);
    clock.advance_ms(250);
    m.record_votes_cast(Round(round), Period(0), CERT, 1);
    clock.advance_ms(500);
    m.record_round_committed(Round(round), committed);
}

// ---------------------------------------------------------------------------
// Zero-events case
// ---------------------------------------------------------------------------

#[test]
fn fresh_metrics_snapshot_is_all_zero() {
    let (m, _clock) = harness();
    let s = m.snapshot();

    assert_eq!(s.votes_cast_total, 0);
    assert!(s.votes_cast_by_step.is_empty());
    assert_eq!(s.proposals_made, 0);
    assert_eq!(s.proposal_rounds, 0);
    assert_eq!(s.reproposals, 0);
    assert_eq!(s.proposals_accepted, 0);
    assert_eq!(s.proposals_rejected, 0);
    assert_eq!(s.blocks_committed, 0);
    assert_eq!(s.vote_broadcast_failures, 0);
    assert_eq!(s.rounds_started, 0);
    assert_eq!(s.current_round, 0);
    assert_eq!(s.last_committed_round, 0);
    assert!(s.recent_rounds.is_empty());
    assert_eq!(s.round_duration.count, 0);
    assert_eq!(s.round_duration.mean_ms, 0);
    assert_eq!(s.round_duration.min_ms, 0);
}

#[test]
fn zero_event_snapshot_renders_valid_prometheus_text() {
    let (m, _clock) = harness();
    let text = m.snapshot().to_prometheus_text();

    // A metric family must never disappear between scrapes: with no votes yet
    // we still emit a zero series for the labelled counter.
    assert!(text.contains("algod_rust_agreement_votes_cast_total{step=\"none\"} 0"));
    assert!(text.contains("algod_rust_agreement_votes_total 0"));
    assert!(text.contains("algod_rust_agreement_blocks_committed_total 0"));
    // Every series must be preceded by HELP/TYPE metadata.
    for line in text.lines() {
        assert!(!line.is_empty(), "no blank lines in exposition output");
    }
    assert!(text.ends_with('\n'));
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

#[test]
fn votes_cast_increments_total_and_per_step() {
    let (m, _clock) = harness();
    m.record_round_started(Round(10));

    m.record_votes_cast(Round(10), Period(0), SOFT, 1);
    m.record_votes_cast(Round(10), Period(0), CERT, 2);
    m.record_votes_cast(Round(10), Period(0), SOFT, 3);

    let s = m.snapshot();
    assert_eq!(s.votes_cast_total, 6);
    assert_eq!(s.votes_cast_by_step.get("soft"), Some(&4));
    assert_eq!(s.votes_cast_by_step.get("cert"), Some(&2));
    assert_eq!(s.votes_cast_by_step.get("next"), None);
}

#[test]
fn vote_step_labels_use_agreement_step_names() {
    let (m, _clock) = harness();
    m.record_round_started(Round(1));
    m.record_votes_cast(Round(1), Period(0), PROPOSE, 1);
    m.record_votes_cast(Round(1), Period(1), Step(5), 1);

    let s = m.snapshot();
    assert_eq!(s.votes_cast_by_step.get("propose"), Some(&1));
    // Step 5 is the second recovery step: `next+2` in agreement's own naming.
    assert_eq!(s.votes_cast_by_step.get("next+2"), Some(&1));
}

#[test]
fn zero_count_vote_is_ignored() {
    let (m, _clock) = harness();
    m.record_round_started(Round(3));
    m.record_votes_cast(Round(3), Period(0), SOFT, 0);

    let s = m.snapshot();
    assert_eq!(s.votes_cast_total, 0);
    assert!(s.votes_cast_by_step.is_empty());
}

#[test]
fn proposals_made_counts_messages_and_rounds() {
    let (m, _clock) = harness();
    m.record_round_started(Round(7));
    // Two local accounts won sortition in the same round.
    m.record_proposal_made(Round(7), Period(0), &[digest(1), digest(2)]);

    let s = m.snapshot();
    assert_eq!(s.proposals_made, 2);
    assert_eq!(s.proposal_rounds, 1);
}

#[test]
fn empty_proposal_batch_is_not_counted() {
    let (m, _clock) = harness();
    m.record_round_started(Round(7));
    m.record_proposal_made(Round(7), Period(0), &[]);

    let s = m.snapshot();
    assert_eq!(s.proposals_made, 0);
    assert_eq!(s.proposal_rounds, 0);
    assert_eq!(s.round_start_to_proposal.count, 0);
}

#[test]
fn reproposal_and_broadcast_failure_counters() {
    let (m, _clock) = harness();
    m.record_reproposal(Round(9), Period(1));
    m.record_reproposal(Round(9), Period(2));
    m.record_vote_broadcast_failure();

    let s = m.snapshot();
    assert_eq!(s.reproposals, 2);
    assert_eq!(s.vote_broadcast_failures, 1);
}

#[test]
fn own_proposal_committed_counts_as_accepted() {
    let (m, clock) = harness();
    run_round(&m, &clock, 20, Some(digest(9)), digest(9));

    let s = m.snapshot();
    assert_eq!(s.proposals_accepted, 1);
    assert_eq!(s.proposals_rejected, 0);
    assert_eq!(s.blocks_committed, 1);
    assert_eq!(s.last_committed_round, 20);
    assert!(s.recent_rounds[0].proposal_accepted);
}

#[test]
fn own_proposal_losing_the_round_counts_as_rejected() {
    let (m, clock) = harness();
    run_round(&m, &clock, 21, Some(digest(9)), digest(4));

    let s = m.snapshot();
    assert_eq!(s.proposals_accepted, 0);
    assert_eq!(s.proposals_rejected, 1);
    assert!(!s.recent_rounds[0].proposal_accepted);
}

#[test]
fn round_with_no_local_proposal_is_neither_accepted_nor_rejected() {
    let (m, clock) = harness();
    run_round(&m, &clock, 22, None, digest(4));

    let s = m.snapshot();
    assert_eq!(s.proposals_accepted, 0);
    assert_eq!(s.proposals_rejected, 0);
    assert_eq!(s.blocks_committed, 1);
    assert!(!s.recent_rounds[0].proposed);
}

#[test]
fn rounds_started_tracks_current_round() {
    let (m, _clock) = harness();
    m.record_round_started(Round(100));
    m.record_round_started(Round(101));
    m.record_round_started(Round(102));

    let s = m.snapshot();
    assert_eq!(s.rounds_started, 3);
    assert_eq!(s.current_round, 102);
}

#[test]
fn repeated_rezero_for_the_same_round_does_not_restart_the_round() {
    let (m, clock) = harness();
    m.record_round_started(Round(50));
    clock.advance_ms(400);
    // A second Rezero for the round already in progress (period change) must
    // not rewind the round-start stamp, or the node would look artificially
    // fast in the timing series.
    m.record_round_started(Round(50));
    clock.advance_ms(100);
    m.record_votes_cast(Round(50), Period(1), SOFT, 1);

    let s = m.snapshot();
    assert_eq!(s.rounds_started, 1);
    assert_eq!(s.round_start_to_first_vote.last_ms, 500);
}

// ---------------------------------------------------------------------------
// Round timing
// ---------------------------------------------------------------------------

#[test]
fn round_timing_measures_from_round_start() {
    let (m, clock) = harness();
    m.record_round_started(Round(30));
    clock.advance_ms(120);
    m.record_proposal_made(Round(30), Period(0), &[digest(1)]);
    clock.advance_ms(80);
    m.record_votes_cast(Round(30), Period(0), SOFT, 1);
    clock.advance_ms(300);
    m.record_round_committed(Round(30), digest(1));

    let s = m.snapshot();
    assert_eq!(s.round_start_to_proposal.last_ms, 120);
    assert_eq!(s.round_start_to_first_vote.last_ms, 200);
    assert_eq!(s.round_duration.last_ms, 500);

    let sample = &s.recent_rounds[0];
    assert_eq!(sample.round, 30);
    assert_eq!(sample.start_to_proposal_ms, Some(120));
    assert_eq!(sample.start_to_first_vote_ms, Some(200));
    assert_eq!(sample.start_to_commit_ms, Some(500));
    assert_eq!(sample.votes_cast, 1);
}

#[test]
fn only_the_first_vote_of_a_round_sets_the_first_vote_timing() {
    let (m, clock) = harness();
    m.record_round_started(Round(31));
    clock.advance_ms(50);
    m.record_votes_cast(Round(31), Period(0), SOFT, 1);
    clock.advance_ms(900);
    m.record_votes_cast(Round(31), Period(0), CERT, 1);

    let s = m.snapshot();
    assert_eq!(s.round_start_to_first_vote.count, 1);
    assert_eq!(s.round_start_to_first_vote.last_ms, 50);
}

#[test]
fn timing_stats_aggregate_across_rounds() {
    let (m, clock) = harness();
    // Three rounds with commit latencies of 1000ms each (100+150+250+500).
    for r in 40..43 {
        run_round(&m, &clock, r, None, digest(1));
    }

    let s = m.snapshot();
    assert_eq!(s.round_duration.count, 3);
    assert_eq!(s.round_duration.min_ms, 1000);
    assert_eq!(s.round_duration.max_ms, 1000);
    assert_eq!(s.round_duration.mean_ms, 1000);
    assert_eq!(s.round_duration.sum_ms, 3000);
}

#[test]
fn min_and_max_track_varying_round_durations() {
    let (m, clock) = harness();

    m.record_round_started(Round(60));
    clock.advance_ms(2000);
    m.record_round_committed(Round(60), digest(1));

    m.record_round_started(Round(61));
    clock.advance_ms(500);
    m.record_round_committed(Round(61), digest(1));

    let s = m.snapshot();
    assert_eq!(s.round_duration.count, 2);
    assert_eq!(s.round_duration.min_ms, 500);
    assert_eq!(s.round_duration.max_ms, 2000);
    assert_eq!(s.round_duration.mean_ms, 1250);
}

#[test]
fn commit_without_a_recorded_round_start_emits_no_timing_sample() {
    let (m, clock) = harness();
    clock.advance_ms(750);
    // Catchup committed a block before agreement ever stamped a round start.
    m.record_round_committed(Round(5), digest(1));

    let s = m.snapshot();
    assert_eq!(s.blocks_committed, 1);
    assert_eq!(s.last_committed_round, 5);
    assert_eq!(s.round_duration.count, 0, "no fabricated duration");
    assert!(s.recent_rounds.is_empty());
}

#[test]
fn an_uncommitted_round_is_still_flushed_to_recent_history() {
    let (m, clock) = harness();
    m.record_round_started(Round(70));
    clock.advance_ms(100);
    m.record_votes_cast(Round(70), Period(0), SOFT, 1);
    // Round 70 never commits locally (catchup jumps us forward).
    m.record_round_started(Round(75));

    let s = m.snapshot();
    assert_eq!(s.recent_rounds.len(), 1);
    assert_eq!(s.recent_rounds[0].round, 70);
    assert_eq!(s.recent_rounds[0].start_to_commit_ms, None);
    assert_eq!(s.round_duration.count, 0);
}

#[test]
fn recent_rounds_history_is_capped() {
    let (m, clock) = harness();
    let total = RECENT_ROUND_CAPACITY as u64 + 10;
    for r in 1..=total {
        run_round(&m, &clock, r, None, digest(1));
    }

    let s = m.snapshot();
    assert_eq!(s.recent_rounds.len(), RECENT_ROUND_CAPACITY);
    // Oldest first, newest last.
    assert_eq!(
        s.recent_rounds[0].round,
        total - RECENT_ROUND_CAPACITY as u64 + 1
    );
    assert_eq!(s.recent_rounds[RECENT_ROUND_CAPACITY - 1].round, total);
}

#[test]
fn uptime_tracks_the_injected_clock() {
    let (m, clock) = harness();
    clock.advance_ms(4321);
    assert_eq!(m.snapshot().uptime_ms, 4321);
}

// ---------------------------------------------------------------------------
// Exposition
// ---------------------------------------------------------------------------

#[test]
fn prometheus_text_reports_real_counts() {
    let (m, clock) = harness();
    run_round(&m, &clock, 80, Some(digest(3)), digest(3));

    let text = m.snapshot().to_prometheus_text();
    assert!(text.contains("algod_rust_agreement_votes_cast_total{step=\"soft\"} 1"));
    assert!(text.contains("algod_rust_agreement_votes_cast_total{step=\"cert\"} 1"));
    assert!(text.contains("algod_rust_agreement_votes_total 2"));
    assert!(text.contains("algod_rust_agreement_proposals_made_total 1"));
    assert!(text.contains("algod_rust_agreement_proposals_accepted_total 1"));
    assert!(text.contains("algod_rust_agreement_last_committed_round 80"));
    assert!(text.contains("algod_rust_agreement_round_duration_milliseconds{stat=\"last\"} 1000"));
    // Every HELP has a matching TYPE.
    let helps = text.lines().filter(|l| l.starts_with("# HELP")).count();
    let types = text.lines().filter(|l| l.starts_with("# TYPE")).count();
    assert_eq!(helps, types);
}

#[test]
fn snapshot_json_roundtrips() {
    let (m, clock) = harness();
    run_round(&m, &clock, 90, Some(digest(3)), digest(3));

    let s = m.snapshot();
    let json = serde_json::to_string(&s).expect("snapshot serializes");
    // Field names are the wire contract consumed by ops/mixed-cluster tooling.
    assert!(json.contains("\"votes_cast_total\":2"));
    assert!(json.contains("\"last_committed_round\":90"));
    assert!(json.contains("\"recent_rounds\""));

    let back: ParticipationSnapshot = serde_json::from_str(&json).expect("snapshot deserializes");
    assert_eq!(back, s);
}

#[test]
fn metrics_are_safe_across_threads() {
    let (m, _clock) = harness();
    m.record_round_started(Round(200));

    let mut handles = Vec::new();
    for _ in 0..4 {
        let m = m.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..250 {
                m.record_votes_cast(Round(200), Period(0), SOFT, 1);
            }
        }));
    }
    for h in handles {
        h.join().expect("worker thread");
    }

    assert_eq!(m.snapshot().votes_cast_total, 1000);
}
