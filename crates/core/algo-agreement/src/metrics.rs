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

//! In-process consensus-participation metrics for the agreement service.
//!
//! Issue #473 (Epic 42f). The agreement service used to report participation
//! only through free-form `info!` format strings, which meant the mixed-cluster
//! soak tooling had to `docker logs | grep` its way to a vote count. This
//! module adds a small, allocation-light counter set that the service updates
//! at the same points it logs, plus per-round wall-clock timings so
//! "the Rust node keeps pace with the Go nodes" is machine-verifiable rather
//! than inferred from block cadence.
//!
//! ## Exposition format
//!
//! Both shapes are rendered from one [`ParticipationSnapshot`]:
//!
//! * [`ParticipationSnapshot`] serializes to JSON for
//!   `GET /v2/participation/status` (the documented, primary interface — it
//!   carries the per-round timing samples, which do not fit a flat counter
//!   model well).
//! * [`ParticipationSnapshot::to_prometheus_text`] renders the OpenMetrics
//!   text exposition for `GET /metrics`, hand-written so the workspace gains
//!   **no** new `prometheus`/`metrics` crate dependency.
//!
//! ## Concurrency
//!
//! The agreement service touches these counters a handful of times per round
//! (one round is ~3 s), from exactly two threads (the main loop and the demux
//! loop), so a single `Mutex` is both simpler and easier to reason about than
//! a bag of atomics that could be read in an inconsistent mix. Every mutating
//! method takes the lock for a few field updates and releases it; no
//! agreement-critical work happens under the lock.
//!
//! ## Clock injection
//!
//! Timing is measured off a [`MetricsClock`], which production wires to a
//! monotonic [`Instant`] taken at construction. Tests inject
//! [`ManualMetricsClock`] so timing assertions are deterministic and take no
//! wall-clock time.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use algo_types::{Digest, Round};

use crate::step::{Period, Step};

/// Number of most-recent rounds retained as individual timing samples.
///
/// Sized so a scraper polling every few seconds still sees every round's
/// sample at Algorand's ~3 s cadence, while keeping the JSON response small
/// and the memory footprint fixed.
pub const RECENT_ROUND_CAPACITY: usize = 64;

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

/// Monotonic time source for metric timings.
///
/// Returns time elapsed since the metrics object was created, so callers never
/// have to deal with a shared epoch.
pub trait MetricsClock: Send + Sync + std::fmt::Debug {
    /// Elapsed time since this clock's zero point.
    fn elapsed(&self) -> Duration;
}

/// Production clock: monotonic [`Instant`] captured at construction.
#[derive(Debug)]
pub struct SystemMetricsClock {
    zero: Instant,
}

impl SystemMetricsClock {
    /// Create a clock whose zero point is now.
    pub fn new() -> Self {
        Self {
            zero: Instant::now(),
        }
    }
}

impl Default for SystemMetricsClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsClock for SystemMetricsClock {
    fn elapsed(&self) -> Duration {
        self.zero.elapsed()
    }
}

/// Test clock whose elapsed time is advanced explicitly.
#[derive(Debug, Default)]
pub struct ManualMetricsClock {
    elapsed: Mutex<Duration>,
}

impl ManualMetricsClock {
    /// Create a clock sitting at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Advance the clock by `delta`.
    pub fn advance(&self, delta: Duration) {
        let mut guard = self.elapsed.lock().expect("manual clock poisoned");
        *guard += delta;
    }

    /// Advance the clock by `millis` milliseconds.
    pub fn advance_ms(&self, millis: u64) {
        self.advance(Duration::from_millis(millis));
    }
}

impl MetricsClock for ManualMetricsClock {
    fn elapsed(&self) -> Duration {
        *self.elapsed.lock().expect("manual clock poisoned")
    }
}

// ---------------------------------------------------------------------------
// Snapshot types
// ---------------------------------------------------------------------------

/// Summary statistics for one timing series, in milliseconds.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimingStats {
    /// Number of samples recorded.
    pub count: u64,
    /// Most recent sample.
    pub last_ms: u64,
    /// Smallest sample seen (0 when `count == 0`).
    pub min_ms: u64,
    /// Largest sample seen.
    pub max_ms: u64,
    /// Mean of all samples, rounded down (0 when `count == 0`).
    pub mean_ms: u64,
    /// Sum of all samples. Exposed so a scraper can compute its own rate or
    /// re-derive the mean without losing precision to the rounded `mean_ms`.
    pub sum_ms: u64,
}

impl TimingStats {
    fn record(&mut self, sample_ms: u64) {
        if self.count == 0 || sample_ms < self.min_ms {
            self.min_ms = sample_ms;
        }
        if sample_ms > self.max_ms {
            self.max_ms = sample_ms;
        }
        self.count += 1;
        self.last_ms = sample_ms;
        // Running total is derived rather than stored: recompute the mean
        // incrementally so the struct stays a plain snapshot value.
        self.sum_ms += sample_ms;
        self.mean_ms = self.sum_ms / self.count;
    }
}

/// Per-round timing sample.
///
/// `None` means the event did not happen in that round — e.g. the node held
/// no proposer credential, so `start_to_proposal_ms` stays null.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundTimingSample {
    /// The round this sample describes.
    pub round: u64,
    /// Milliseconds from round start to this node's first vote of the round.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_to_first_vote_ms: Option<u64>,
    /// Milliseconds from round start to this node's proposal assembly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_to_proposal_ms: Option<u64>,
    /// Milliseconds from round start to the round being committed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_to_commit_ms: Option<u64>,
    /// Whether this node assembled a proposal in this round.
    pub proposed: bool,
    /// Whether this node's proposal is the one that got committed.
    pub proposal_accepted: bool,
    /// Votes this node cast in this round.
    pub votes_cast: u64,
}

/// A point-in-time view of the node's consensus participation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipationSnapshot {
    /// Total votes this node cast (proposal-votes included).
    pub votes_cast_total: u64,
    /// Votes cast, keyed by step name (`propose`, `soft`, `cert`, `next+1`, …).
    pub votes_cast_by_step: BTreeMap<String, u64>,
    /// Proposal messages this node assembled (a round can yield more than one
    /// when several local accounts win sortition).
    pub proposals_made: u64,
    /// Rounds in which this node assembled at least one proposal.
    pub proposal_rounds: u64,
    /// Reproposals this node issued (period > 0 recovery).
    pub reproposals: u64,
    /// Rounds where this node proposed and its proposal was the committed one.
    pub proposals_accepted: u64,
    /// Rounds where this node proposed and a different proposal was committed.
    pub proposals_rejected: u64,
    /// Blocks committed by the agreement service since start.
    pub blocks_committed: u64,
    /// Vote broadcasts that failed at the network layer.
    pub vote_broadcast_failures: u64,
    /// Rounds this node has entered since start.
    pub rounds_started: u64,
    /// The round currently being agreed (0 before the first round starts).
    pub current_round: u64,
    /// The highest round committed by agreement (0 before the first commit).
    pub last_committed_round: u64,
    /// Round start → first vote of that round.
    pub round_start_to_first_vote: TimingStats,
    /// Round start → proposal assembly.
    pub round_start_to_proposal: TimingStats,
    /// Round start → commit (effective round wall-clock duration).
    pub round_duration: TimingStats,
    /// The most recent [`RECENT_ROUND_CAPACITY`] completed rounds, oldest first.
    pub recent_rounds: Vec<RoundTimingSample>,
    /// Milliseconds since the metrics object was created.
    pub uptime_ms: u64,
}

impl ParticipationSnapshot {
    /// Render the snapshot as Prometheus text exposition format.
    ///
    /// Hand-written on purpose: the payload is a couple of dozen series, so a
    /// `prometheus` crate dependency would be all cost and no benefit. Metric
    /// names follow the `algod_rust_agreement_*` prefix convention;
    /// counters carry the `_total` suffix as the exposition format requires.
    pub fn to_prometheus_text(&self) -> String {
        let mut out = String::with_capacity(2048);

        // --- counters -----------------------------------------------------
        out.push_str("# HELP algod_rust_agreement_votes_cast_total Agreement votes cast by this node, by step.\n");
        out.push_str("# TYPE algod_rust_agreement_votes_cast_total counter\n");
        if self.votes_cast_by_step.is_empty() {
            // Emit the zero series anyway so a scraper never sees the metric
            // family vanish between scrapes (a missing series and a zero
            // series mean very different things to alerting rules).
            out.push_str("algod_rust_agreement_votes_cast_total{step=\"none\"} 0\n");
        }
        for (step, count) in &self.votes_cast_by_step {
            out.push_str(&format!(
                "algod_rust_agreement_votes_cast_total{{step=\"{}\"}} {}\n",
                escape_label(step),
                count
            ));
        }

        for (name, help, value) in [
            (
                "algod_rust_agreement_votes_total",
                "Total agreement votes cast by this node.",
                self.votes_cast_total,
            ),
            (
                "algod_rust_agreement_proposals_made_total",
                "Proposal messages assembled by this node.",
                self.proposals_made,
            ),
            (
                "algod_rust_agreement_proposal_rounds_total",
                "Rounds in which this node assembled at least one proposal.",
                self.proposal_rounds,
            ),
            (
                "algod_rust_agreement_reproposals_total",
                "Reproposals issued by this node.",
                self.reproposals,
            ),
            (
                "algod_rust_agreement_proposals_accepted_total",
                "Rounds where this node's proposal was the committed one.",
                self.proposals_accepted,
            ),
            (
                "algod_rust_agreement_proposals_rejected_total",
                "Rounds where this node proposed but another proposal was committed.",
                self.proposals_rejected,
            ),
            (
                "algod_rust_agreement_blocks_committed_total",
                "Blocks committed by the agreement service.",
                self.blocks_committed,
            ),
            (
                "algod_rust_agreement_vote_broadcast_failures_total",
                "Vote broadcasts that failed at the network layer.",
                self.vote_broadcast_failures,
            ),
            (
                "algod_rust_agreement_rounds_started_total",
                "Rounds entered by this node.",
                self.rounds_started,
            ),
        ] {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
            ));
        }

        // --- gauges -------------------------------------------------------
        for (name, help, value) in [
            (
                "algod_rust_agreement_current_round",
                "Round currently being agreed.",
                self.current_round,
            ),
            (
                "algod_rust_agreement_last_committed_round",
                "Highest round committed by agreement.",
                self.last_committed_round,
            ),
            (
                "algod_rust_agreement_uptime_milliseconds",
                "Milliseconds since agreement metrics started.",
                self.uptime_ms,
            ),
        ] {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}\n"
            ));
        }

        // --- timing summaries --------------------------------------------
        for (name, help, stats) in [
            (
                "algod_rust_agreement_round_start_to_first_vote_milliseconds",
                "Milliseconds from round start to this node's first vote.",
                &self.round_start_to_first_vote,
            ),
            (
                "algod_rust_agreement_round_start_to_proposal_milliseconds",
                "Milliseconds from round start to this node's proposal assembly.",
                &self.round_start_to_proposal,
            ),
            (
                "algod_rust_agreement_round_duration_milliseconds",
                "Milliseconds from round start to round commit.",
                &self.round_duration,
            ),
        ] {
            out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} gauge\n"));
            out.push_str(&format!("{name}{{stat=\"last\"}} {}\n", stats.last_ms));
            out.push_str(&format!("{name}{{stat=\"min\"}} {}\n", stats.min_ms));
            out.push_str(&format!("{name}{{stat=\"max\"}} {}\n", stats.max_ms));
            out.push_str(&format!("{name}{{stat=\"mean\"}} {}\n", stats.mean_ms));
            out.push_str(&format!("{name}{{stat=\"count\"}} {}\n", stats.count));
        }

        out
    }
}

/// Escape a Prometheus label value (`\`, `"`, and newline).
fn escape_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Collector
// ---------------------------------------------------------------------------

/// Mutable state behind the collector's lock.
#[derive(Debug, Default)]
struct MetricsInner {
    votes_cast_total: u64,
    votes_cast_by_step: BTreeMap<String, u64>,
    proposals_made: u64,
    proposal_rounds: u64,
    reproposals: u64,
    proposals_accepted: u64,
    proposals_rejected: u64,
    blocks_committed: u64,
    vote_broadcast_failures: u64,
    rounds_started: u64,
    current_round: u64,
    last_committed_round: u64,
    first_vote: TimingStats,
    proposal: TimingStats,
    duration: TimingStats,
    recent: VecDeque<RoundTimingSample>,

    /// Wall-clock offset at which `current_round` started.
    round_start: Option<Duration>,
    /// In-progress sample for `current_round`.
    live: RoundTimingSample,
    /// Block digests this node proposed in `current_round`.
    live_digests: HashSet<Digest>,
}

/// Consensus-participation counters and timings.
///
/// Cloneable handles are obtained by wrapping in `Arc`; the agreement service
/// hands one `Arc<ParticipationMetrics>` to its main loop and one to its demux
/// loop, and the REST adapter keeps a third for scraping.
#[derive(Debug)]
pub struct ParticipationMetrics {
    inner: Mutex<MetricsInner>,
    clock: Arc<dyn MetricsClock>,
}

impl Default for ParticipationMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ParticipationMetrics {
    /// Create a collector driven by the monotonic system clock.
    pub fn new() -> Self {
        Self::with_clock(Arc::new(SystemMetricsClock::new()))
    }

    /// Create a collector driven by an injected clock (tests).
    pub fn with_clock(clock: Arc<dyn MetricsClock>) -> Self {
        Self {
            inner: Mutex::new(MetricsInner::default()),
            clock,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MetricsInner> {
        // A poisoned metrics mutex must never take down consensus: the data is
        // observability-only, so recover the guard and carry on.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Record that the node entered `round` (the agreement `Rezero` action).
    ///
    /// This is the definition of "round start" for every timing in this
    /// module. A repeated call for the round already in progress is ignored so
    /// a mid-round rezero cannot silently restart the clock and make the node
    /// look faster than it is.
    pub fn record_round_started(&self, round: Round) {
        let now = self.clock.elapsed();
        let mut m = self.lock();
        if m.round_start.is_some() && m.current_round == round.0 {
            return;
        }
        // Flush any in-progress sample that never reached a commit (e.g. the
        // round was resolved by catchup rather than by agreement here).
        if m.round_start.is_some() {
            let live = std::mem::take(&mut m.live);
            push_recent(&mut m.recent, live);
        }
        m.rounds_started += 1;
        m.current_round = round.0;
        m.round_start = Some(now);
        m.live = RoundTimingSample {
            round: round.0,
            ..RoundTimingSample::default()
        };
        m.live_digests.clear();
    }

    /// Record that the node assembled `digests.len()` proposal messages.
    pub fn record_proposal_made(&self, round: Round, _period: Period, digests: &[Digest]) {
        if digests.is_empty() {
            return;
        }
        let now = self.clock.elapsed();
        let mut m = self.lock();
        m.proposals_made += digests.len() as u64;
        if m.current_round == round.0 {
            if !m.live.proposed {
                m.proposal_rounds += 1;
                let elapsed = round_elapsed_ms(&m, now);
                if let Some(elapsed) = elapsed {
                    m.live.start_to_proposal_ms = Some(elapsed);
                    m.proposal.record(elapsed);
                }
            }
            m.live.proposed = true;
            for d in digests {
                m.live_digests.insert(*d);
            }
        } else {
            // Assembly for a round other than the one in progress (bootstrap
            // assembles before the first Rezero is observed): still count the
            // proposal, but do not attribute timing to a round we never
            // stamped a start for.
            m.proposal_rounds += 1;
        }
    }

    /// Record a reproposal (period-recovery `Repropose` action).
    pub fn record_reproposal(&self, _round: Round, _period: Period) {
        let mut m = self.lock();
        m.reproposals += 1;
    }

    /// Record `count` votes cast at `step`.
    pub fn record_votes_cast(&self, round: Round, _period: Period, step: Step, count: u64) {
        if count == 0 {
            return;
        }
        let now = self.clock.elapsed();
        let mut m = self.lock();
        m.votes_cast_total += count;
        *m.votes_cast_by_step.entry(step.to_string()).or_insert(0) += count;
        if m.current_round == round.0 {
            m.live.votes_cast += count;
            if m.live.start_to_first_vote_ms.is_none() {
                let elapsed = round_elapsed_ms(&m, now);
                if let Some(elapsed) = elapsed {
                    m.live.start_to_first_vote_ms = Some(elapsed);
                    m.first_vote.record(elapsed);
                }
            }
        }
    }

    /// Record a failed vote broadcast.
    pub fn record_vote_broadcast_failure(&self) {
        let mut m = self.lock();
        m.vote_broadcast_failures += 1;
    }

    /// Record that agreement committed `round` with `block_digest`.
    ///
    /// Closes out the in-progress timing sample and decides whether this
    /// node's own proposal (if any) was the one that won the round.
    pub fn record_round_committed(&self, round: Round, block_digest: Digest) {
        let now = self.clock.elapsed();
        let mut m = self.lock();
        m.blocks_committed += 1;
        if round.0 > m.last_committed_round {
            m.last_committed_round = round.0;
        }
        if m.current_round != round.0 || m.round_start.is_none() {
            // Committed a round we never stamped a start for (catchup, or a
            // commit that arrived before the first Rezero). Counted above, but
            // no timing sample is emitted — a fabricated duration here would
            // corrupt the "keeps pace with Go" comparison.
            return;
        }
        let elapsed = round_elapsed_ms(&m, now);
        if let Some(elapsed) = elapsed {
            m.live.start_to_commit_ms = Some(elapsed);
            m.duration.record(elapsed);
        }
        if m.live.proposed {
            if m.live_digests.contains(&block_digest) {
                m.proposals_accepted += 1;
                m.live.proposal_accepted = true;
            } else {
                m.proposals_rejected += 1;
            }
        }
        let live = std::mem::take(&mut m.live);
        push_recent(&mut m.recent, live);
        m.round_start = None;
    }

    /// Take a consistent snapshot of every counter and timing.
    pub fn snapshot(&self) -> ParticipationSnapshot {
        let uptime = self.clock.elapsed();
        let m = self.lock();
        ParticipationSnapshot {
            votes_cast_total: m.votes_cast_total,
            votes_cast_by_step: m.votes_cast_by_step.clone(),
            proposals_made: m.proposals_made,
            proposal_rounds: m.proposal_rounds,
            reproposals: m.reproposals,
            proposals_accepted: m.proposals_accepted,
            proposals_rejected: m.proposals_rejected,
            blocks_committed: m.blocks_committed,
            vote_broadcast_failures: m.vote_broadcast_failures,
            rounds_started: m.rounds_started,
            current_round: m.current_round,
            last_committed_round: m.last_committed_round,
            round_start_to_first_vote: m.first_vote.clone(),
            round_start_to_proposal: m.proposal.clone(),
            round_duration: m.duration.clone(),
            recent_rounds: m.recent.iter().cloned().collect(),
            uptime_ms: uptime.as_millis() as u64,
        }
    }
}

/// Milliseconds since the in-progress round started, or `None` if no start
/// stamp exists. Saturating: a clock that appears to move backwards yields 0
/// rather than a wrapped, absurd duration.
fn round_elapsed_ms(m: &MetricsInner, now: Duration) -> Option<u64> {
    let start = m.round_start?;
    Some(now.saturating_sub(start).as_millis() as u64)
}

fn push_recent(recent: &mut VecDeque<RoundTimingSample>, sample: RoundTimingSample) {
    if sample.round == 0 {
        return;
    }
    recent.push_back(sample);
    while recent.len() > RECENT_ROUND_CAPACITY {
        recent.pop_front();
    }
}
