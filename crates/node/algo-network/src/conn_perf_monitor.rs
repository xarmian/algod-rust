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

//! Outgoing-connection performance monitor (issue #1088, Phase 17 gap).
//!
//! Ports the *algorithm* of go-algorand's `network/connPerfMon.go`
//! `connectionPerformanceMonitor` at `v5.0.0-stable`: watch a fixed set of
//! monitored peers through a presync/sync/accumulate/stopping/stopped stage
//! pipeline, measuring how much each peer lags behind whichever peer
//! delivers each (deduplicated, digest-identified) message first, and how
//! often each peer is first. The result feeds a "which outgoing peer should
//! we drop for being consistently slow" decision.
//!
//! # Scope (deliberately standalone, following issue #819's `peer_ranker`
//! precedent)
//!
//! This module ports [`ConnectionPerformanceMonitor`] and
//! [`NetworkAdvanceMonitor`] — the stage state machine, message-bucket
//! accumulation/pruning, and per-peer statistics — as pure, self-contained
//! logic operating on peer addresses (`String`, matching
//! [`crate::message::IncomingMessage::sender`]) and
//! [`crate::message::IncomingMessage`] directly. It does **not** port go's
//! `outgoingConnsCloser`/`checkExistingConnectionsNeedDisconnecting`, which
//! wires this monitor's statistics into an actual disconnect decision via
//! `wsPeer.throttledOutgoingConnection` and a clique-resolution disconnect
//! call — that needs a live-peer-throttling/disconnect surface algod-rust's
//! `WebsocketNetwork` doesn't yet expose in a form this monitor could drive
//! (see the follow-up issue filed alongside this port). Wiring this into a
//! real "drop the worst outgoing peer" mesh-maintenance decision is left as
//! documented follow-up, exactly as `peer_ranker.rs` documents for its own
//! not-yet-wired ranking algorithm.
//!
//! # go-algorand correspondence
//!
//! | Go (`network/connPerfMon.go`)         | Rust (this module)                    |
//! |----------------------------------------|----------------------------------------|
//! | `pmStage`                               | [`PmStage`]                            |
//! | `pmMessage`                             | `PmMessage` (private)                  |
//! | `pmPeerStatistics`                      | [`PmPeerStatistics`]                   |
//! | `pmStatistics`                          | [`PmStatistics`]                       |
//! | `pmPendingMessageBucket`                | `PmPendingMessageBucket` (private)      |
//! | `connectionPerformanceMonitor`          | [`ConnectionPerformanceMonitor`]       |
//! | `networkAdvanceMonitor`                 | [`NetworkAdvanceMonitor`]              |

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use rand::Rng;

use crate::message::IncomingMessage;
use crate::message_filter::generate_message_digest;
use crate::tag::Tag;

// ---------------------------------------------------------------------------
// Timing constants (connPerfMon.go lines 40-50)
// ---------------------------------------------------------------------------

const PM_PRESYNC_TIME: i64 = 10_000_000_000; // 10s in nanoseconds
const PM_SYNC_IDLE_TIME: i64 = 2_000_000_000; // 2s
const PM_SYNC_MAX_TIME: i64 = 25_000_000_000; // 25s
const PM_ACCUMULATION_TIME: i64 = 60_000_000_000; // 60s
const PM_ACCUMULATION_TIME_RANGE: i64 = 30_000_000_000; // 30s
const PM_ACCUMULATION_IDLING_TIME: i64 = 2_000_000_000; // 2s
const PM_MAX_MESSAGE_WAIT_TIME: i64 = 15_000_000_000; // 15s
const PM_UNDELIVERED_MESSAGE_PENALTY_TIME: i64 = 5_000_000_000; // 5s
const PM_MESSAGE_BUCKET_DURATION: i64 = 1_000_000_000; // 1s

/// The performance-monitoring stage. Mirrors go's `pmStage` (`iota`
/// ordering matters — [`ConnectionPerformanceMonitor::notify`] dispatches
/// on it, and tests assert on the numeric progression).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PmStage {
    /// Warmup: wait for at least one message from every peer, and for
    /// enough elapsed time, before attempting to sync up.
    Presync,
    /// Syncing up the peer message streams; ends once all connections have
    /// gone idle for a bit.
    Sync,
    /// Monitoring streams and accumulating messages between connections.
    Accumulate,
    /// Keep monitoring, but stop accepting new messages; drain pending
    /// messages until all have expired.
    Stopping,
    /// Final stage: a conclusion has been reached.
    Stopped,
}

/// One pending message's per-peer arrival times, keyed by message digest.
struct PmMessage {
    peer_msg_time: HashMap<String, i64>,
    first_peer_time: i64,
}

/// A time-bucketed group of pending messages awaiting full delivery.
struct PmPendingMessageBucket {
    messages: HashMap<[u8; 32], PmMessage>,
    start_time: i64,
    end_time: i64,
}

/// One peer's resulting performance statistics.
#[derive(Debug, Clone, PartialEq)]
pub struct PmPeerStatistics {
    /// The peer's address.
    pub peer: String,
    /// The peer's average relative message delay, in nanoseconds.
    pub peer_delay: i64,
    /// The fraction of messages this peer delivered before any other peer.
    pub peer_first_message: f32,
}

/// The resulting dataset of a completed performance-monitoring run.
#[derive(Debug, Clone, PartialEq)]
pub struct PmStatistics {
    /// Peers ordered by descending delay (worst-performing first).
    pub peer_statistics: Vec<PmPeerStatistics>,
    /// The number of messages used to calculate the above statistics.
    pub message_count: i64,
}

/// Watches a fixed set of outgoing peers' message-delivery timing to
/// determine which (if any) is consistently the slowest. See the module
/// docs for the go correspondence and scope.
pub struct ConnectionPerformanceMonitor {
    monitored_connections: HashSet<String>,
    monitored_message_tags: HashSet<Tag>,
    stage: PmStage,
    peer_last_msg_time: HashMap<String, i64>,
    last_incoming_msg_time: i64,
    stage_start_time: i64,
    pending_messages_buckets: Vec<PmPendingMessageBucket>,
    connection_delay: HashMap<String, i64>,
    first_message_count: HashMap<String, i64>,
    msg_count: i64,
    accumulation_time: i64,
}

impl ConnectionPerformanceMonitor {
    /// Creates a new monitor configured to watch messages carrying any of
    /// `message_tags` (go: `makeConnectionPerformanceMonitor`).
    pub fn new(message_tags: &[Tag]) -> Self {
        Self {
            monitored_connections: HashSet::new(),
            monitored_message_tags: message_tags.iter().copied().collect(),
            stage: PmStage::Presync,
            peer_last_msg_time: HashMap::new(),
            last_incoming_msg_time: 0,
            stage_start_time: 0,
            pending_messages_buckets: Vec::new(),
            connection_delay: HashMap::new(),
            first_message_count: HashMap::new(),
            msg_count: 0,
            accumulation_time: 0,
        }
    }

    /// Returns the current stage. Exposed for tests/diagnostics (go's
    /// `perfMonitor.stage` is package-private but tests read it directly).
    pub fn stage(&self) -> PmStage {
        self.stage
    }

    /// Returns the performance-monitoring result, once available; `None`
    /// while the monitor is still running (go: `GetPeersStatistics`).
    pub fn get_peers_statistics(&self) -> Option<PmStatistics> {
        if self.stage != PmStage::Stopped || self.connection_delay.is_empty() {
            return None;
        }
        let mut peer_statistics: Vec<PmPeerStatistics> = self
            .connection_delay
            .iter()
            .map(|(peer, &delay)| {
                let peer_first_message = if self.msg_count > 0 {
                    *self.first_message_count.get(peer).unwrap_or(&0) as f32 / self.msg_count as f32
                } else {
                    0.0
                };
                PmPeerStatistics {
                    peer: peer.clone(),
                    peer_delay: delay,
                    peer_first_message,
                }
            })
            .collect();
        peer_statistics.sort_by_key(|ps| std::cmp::Reverse(ps.peer_delay));
        Some(PmStatistics {
            peer_statistics,
            message_count: self.msg_count,
        })
    }

    /// Returns `true` if `peers` is (order-insensitively) exactly the set
    /// of currently monitored peers (go: `ComparePeers`).
    pub fn compare_peers(&self, peers: &[String]) -> bool {
        for peer in peers {
            if !self.monitored_connections.contains(peer) {
                return false;
            }
        }
        peers.len() == self.monitored_connections.len()
    }

    /// Resets monitoring to watch exactly `peers`, starting a fresh
    /// presync stage (go: `Reset`). `now` is the current time in
    /// nanoseconds since an arbitrary epoch (matches
    /// [`IncomingMessage::received_at`]'s clock).
    pub fn reset(&mut self, peers: &[String], now: i64) {
        self.monitored_connections = peers.iter().cloned().collect();
        self.peer_last_msg_time = HashMap::with_capacity(peers.len());
        self.connection_delay = HashMap::with_capacity(peers.len());
        self.first_message_count = HashMap::with_capacity(peers.len());
        self.msg_count = 0;
        self.advance_stage(PmStage::Presync, now);
        self.accumulation_time = PM_ACCUMULATION_TIME + rand_i64_below(PM_ACCUMULATION_TIME.max(1));

        for peer in peers {
            self.peer_last_msg_time
                .insert(peer.clone(), self.stage_start_time);
            self.connection_delay.insert(peer.clone(), 0);
            self.first_message_count.insert(peer.clone(), 0);
        }
    }

    /// Processes one incoming message (go: `Notify`).
    pub fn notify(&mut self, msg: &IncomingMessage) {
        if !self.monitored_connections.contains(&msg.sender) {
            return;
        }
        if !self.monitored_message_tags.contains(&msg.tag) {
            return;
        }
        match self.stage {
            PmStage::Presync => self.notify_presync(msg),
            PmStage::Sync => self.notify_sync(msg),
            PmStage::Accumulate => self.notify_accumulate(msg),
            PmStage::Stopping => self.notify_stopping(msg),
            PmStage::Stopped => {}
        }
    }

    fn notify_presync(&mut self, msg: &IncomingMessage) {
        self.peer_last_msg_time
            .insert(msg.sender.clone(), msg.received_at);
        if (msg.received_at - self.stage_start_time) < PM_PRESYNC_TIME {
            return;
        }
        let mut no_msg_peers: HashSet<String> = HashSet::new();
        for (peer, &last_msg_time) in &self.peer_last_msg_time {
            if last_msg_time == self.stage_start_time {
                no_msg_peers.insert(peer.clone());
            }
        }
        if no_msg_peers.len() >= (self.peer_last_msg_time.len() / 2) {
            self.stage_start_time = msg.received_at;
            return;
        }
        if !no_msg_peers.is_empty() {
            self.advance_stage(PmStage::Stopped, msg.received_at);
            for peer in self.monitored_connections.clone() {
                let delay = if no_msg_peers.contains(&peer) {
                    PM_UNDELIVERED_MESSAGE_PENALTY_TIME
                } else {
                    0
                };
                self.connection_delay.insert(peer, delay);
            }
            return;
        }
        self.last_incoming_msg_time = msg.received_at;
        self.advance_stage(PmStage::Sync, msg.received_at);
    }

    fn notify_sync(&mut self, msg: &IncomingMessage) {
        let min_msg_interval = self.update_message_idling_interval(msg.received_at);
        if min_msg_interval > PM_SYNC_IDLE_TIME
            || (msg.received_at - self.stage_start_time > PM_SYNC_MAX_TIME)
        {
            self.accumulate_message(msg, true);
            self.advance_stage(PmStage::Accumulate, msg.received_at);
        }
    }

    fn notify_accumulate(&mut self, msg: &IncomingMessage) {
        let min_msg_interval = self.update_message_idling_interval(msg.received_at);
        if msg.received_at - self.stage_start_time >= self.accumulation_time
            && (min_msg_interval > PM_ACCUMULATION_IDLING_TIME
                || (msg.received_at - self.stage_start_time
                    >= self.accumulation_time + PM_ACCUMULATION_TIME_RANGE))
        {
            self.advance_stage(PmStage::Stopping, msg.received_at);
            return;
        }
        self.accumulate_message(msg, true);
        self.prune_old_messages(msg.received_at);
    }

    fn notify_stopping(&mut self, msg: &IncomingMessage) {
        self.accumulate_message(msg, false);
        self.prune_old_messages(msg.received_at);
        if !self.pending_messages_buckets.is_empty() {
            return;
        }
        if self.msg_count > 0 {
            for delay in self.connection_delay.values_mut() {
                *delay /= self.msg_count;
            }
        }
        self.advance_stage(PmStage::Stopped, msg.received_at);
    }

    fn advance_stage(&mut self, new_stage: PmStage, now: i64) {
        self.stage = new_stage;
        self.stage_start_time = now;
    }

    fn update_message_idling_interval(&mut self, now: i64) -> i64 {
        let current_incoming_msg_time = self.last_incoming_msg_time;
        if self.last_incoming_msg_time < now {
            self.last_incoming_msg_time = now;
        }
        if current_incoming_msg_time <= now {
            now - current_incoming_msg_time
        } else {
            0
        }
    }

    /// Drops (and folds delay accounting for) any pending-message buckets
    /// whose end time is older than `now - pmMaxMessageWaitTime` (go:
    /// `pruneOldMessages`). Exposed at `pub(crate)` visibility so tests can
    /// drive it directly with synthetic buckets, mirroring go's
    /// `TestConnMonitor_BucketsPruning` (which pokes the unexported
    /// `pendingMessagesBuckets` field directly).
    pub(crate) fn prune_old_messages(&mut self, now: i64) {
        let oldest_message = now - PM_MAX_MESSAGE_WAIT_TIME;
        let mut kept = Vec::with_capacity(self.pending_messages_buckets.len());
        for bucket in self.pending_messages_buckets.drain(..) {
            if bucket.end_time > oldest_message {
                kept.push(bucket);
                continue;
            }
            for (_, pending_msg) in bucket.messages {
                for peer in self.monitored_connections.clone() {
                    let delay_contribution = match pending_msg.peer_msg_time.get(&peer) {
                        Some(&msg_time) => msg_time - pending_msg.first_peer_time,
                        None => PM_UNDELIVERED_MESSAGE_PENALTY_TIME,
                    };
                    *self.connection_delay.entry(peer).or_insert(0) += delay_contribution;
                }
            }
        }
        self.pending_messages_buckets = kept;
    }

    /// Test-only hook mirroring `TestConnMonitor_BucketsPruning`'s direct
    /// manipulation of `pendingMessagesBuckets` (bucket contents don't
    /// matter for that test — only bucket count/`endTime`).
    #[cfg(test)]
    fn push_test_bucket(&mut self, end_time: i64) {
        self.pending_messages_buckets.push(PmPendingMessageBucket {
            messages: HashMap::new(),
            start_time: 0,
            end_time,
        });
    }

    #[cfg(test)]
    fn pending_bucket_count(&self) -> usize {
        self.pending_messages_buckets.len()
    }

    /// Test-only hook that forces the monitor directly into `Stopped` with
    /// an explicit, deterministic per-peer delay assignment. Used by
    /// `ws_network.rs`'s issue #1105 disconnect-eligibility tests, which
    /// need two *different* nonzero per-peer delays to prove
    /// `check_existing_connections_need_disconnecting` picks the
    /// worst-*eligible* peer rather than the worst overall — the real
    /// `notify`/presync-penalty path (see
    /// `check_existing_connections_need_disconnecting_drops_the_slowest_peer`)
    /// can only ever produce one nonzero delay per run, so it can't build
    /// that scenario. `pub(crate)` (not test-module-private) so the
    /// `algo_network` crate's other test modules can reach it too.
    #[cfg(test)]
    pub(crate) fn force_stopped_with_delays(&mut self, delays: &[(String, i64)]) {
        self.stage = PmStage::Stopped;
        self.connection_delay = delays.iter().cloned().collect();
        // Keep `ComparePeers` matching so the caller's `compare_peers`
        // check doesn't trigger a `reset` that would wipe this back out.
        self.monitored_connections = delays.iter().map(|(peer, _)| peer.clone()).collect();
    }

    fn accumulate_message(&mut self, msg: &IncomingMessage, new_messages: bool) {
        let digest = generate_message_digest(&msg.tag, &msg.data);

        let mut bucket_idx = None;
        let mut found_existing = false;
        for (idx, bucket) in self.pending_messages_buckets.iter().enumerate().rev() {
            if bucket.messages.contains_key(&digest) {
                bucket_idx = Some(idx);
                found_existing = true;
                break;
            }
            if msg.received_at >= bucket.start_time && msg.received_at <= bucket.end_time {
                bucket_idx = Some(idx);
            }
        }

        if !found_existing {
            if !new_messages {
                return;
            }
            let idx = match bucket_idx {
                Some(idx) => idx,
                None => {
                    let start_time =
                        msg.received_at - (msg.received_at % PM_MESSAGE_BUCKET_DURATION);
                    self.pending_messages_buckets.push(PmPendingMessageBucket {
                        messages: HashMap::new(),
                        start_time,
                        end_time: start_time + PM_MESSAGE_BUCKET_DURATION - 1,
                    });
                    self.pending_messages_buckets.len() - 1
                }
            };
            let mut peer_msg_time = HashMap::with_capacity(1);
            peer_msg_time.insert(msg.sender.clone(), msg.received_at);
            self.pending_messages_buckets[idx].messages.insert(
                digest,
                PmMessage {
                    peer_msg_time,
                    first_peer_time: msg.received_at,
                },
            );
            *self
                .first_message_count
                .entry(msg.sender.clone())
                .or_insert(0) += 1;
            self.msg_count += 1;
            return;
        }

        let idx = bucket_idx.expect("found_existing implies bucket_idx is Some");
        let pending_msg = self.pending_messages_buckets[idx]
            .messages
            .get_mut(&digest)
            .expect("digest was just confirmed present");
        pending_msg
            .peer_msg_time
            .insert(msg.sender.clone(), msg.received_at);
        if msg.received_at < pending_msg.first_peer_time {
            pending_msg.first_peer_time = msg.received_at;
        }

        if pending_msg.peer_msg_time.len() == self.monitored_connections.len() {
            for (peer, &msg_time) in &pending_msg.peer_msg_time {
                *self.connection_delay.entry(peer.clone()).or_insert(0) +=
                    msg_time - pending_msg.first_peer_time;
            }
            self.pending_messages_buckets[idx].messages.remove(&digest);
        }
    }
}

/// Returns a random value in `[0, bound)`. A tiny wrapper so
/// [`ConnectionPerformanceMonitor::reset`]'s accumulation-time jitter
/// doesn't need `rand::thread_rng()` spelled out inline, and so `bound == 0`
/// (which `rand`'s range types reject) can't happen (callers pass `.max(1)`).
fn rand_i64_below(bound: i64) -> i64 {
    rand::thread_rng().gen_range(0..bound)
}

/// Tracks whether the agreement protocol has recently made progress, as a
/// watchdog for detecting connectivity issues such as network cliques
/// (go: `networkAdvanceMonitor`).
pub struct NetworkAdvanceMonitor {
    last_network_advance: Instant,
}

impl NetworkAdvanceMonitor {
    /// Creates a monitor whose clock starts now (go:
    /// `makeNetworkAdvanceMonitor`).
    pub fn new() -> Self {
        Self {
            last_network_advance: Instant::now(),
        }
    }

    /// Returns `true` if the last recorded advance was within `interval` of
    /// now (go: `lastAdvancedWithin`).
    pub fn last_advanced_within(&self, interval: Duration) -> bool {
        self.last_network_advance.elapsed() < interval
    }

    /// Records that the network just made progress (go: `updateLastAdvance`).
    pub fn update_last_advance(&mut self) {
        self.last_network_advance = Instant::now();
    }
}

impl Default for NetworkAdvanceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(sender: &str, tag: Tag, data: &[u8], received_at: i64) -> IncomingMessage {
        IncomingMessage {
            tag,
            data: data.to_vec(),
            sender: sender.to_string(),
            received_at,
            peer: None,
        }
    }

    /// Builds a synthetic pool of messages across `peers`, roughly mirroring
    /// go's `makeMsgPool` distribution (some messages from one peer, some
    /// from a few, most from all peers), so a monitor driven by it will
    /// actually reach every stage and terminate.
    fn make_msg_pool(n: usize, peers: &[String]) -> Vec<IncomingMessage> {
        let mut out = Vec::with_capacity(n);
        let mut timer: i64 = 0;
        let msg_per_second: u64 = 500;
        let msg_interval = 1_000_000_000i64 / msg_per_second as i64;
        let mut msg_index: u64 = 0;
        while out.len() < n {
            let data = msg_index.to_le_bytes();
            let senders_count = match msg_index % 10 {
                0 => 1,
                1 | 2 => 2,
                3 | 4 => 3,
                _ => peers.len(),
            };
            for i in 0..senders_count {
                let sender = &peers[(msg_index as usize + i) % peers.len()];
                timer += 7;
                out.push(msg(sender, Tag::AgreementVote, &data, timer));
                if out.len() >= n {
                    break;
                }
            }
            msg_index += 1;
            if msg_index % msg_per_second == 0 {
                timer += 3_000_000_000;
            }
            timer += msg_interval + 123;
        }
        out
    }

    // Mirrors go's `TestConnMonitor_StageTiming`, minus the timing
    // measurement itself (go only prints timing stats — the actual
    // assertion-worthy behavior is "driven by enough traffic, the monitor
    // reaches every stage and eventually produces statistics").
    #[test]
    fn stage_timing_reaches_stopped_and_produces_statistics() {
        let peers: Vec<String> = (0..4).map(|i| format!("peer{i}")).collect();
        let msg_pool = make_msg_pool(60_000, &peers);
        let start_test_time = 1_700_000_000_000_000_000i64;

        let mut mon = ConnectionPerformanceMonitor::new(&[Tag::AgreementVote]);
        mon.reset(&peers, start_test_time);

        let mut seen_stages = HashSet::new();
        seen_stages.insert(mon.stage());
        let mut stats = None;
        for m in &msg_pool {
            let mut m = m.clone_for_test();
            m.received_at += start_test_time;
            mon.notify(&m);
            seen_stages.insert(mon.stage());
            if let Some(s) = mon.get_peers_statistics() {
                stats = Some(s);
                break;
            }
        }

        let stats = stats
            .expect("60000 synthetic messages across 4 peers should be enough to reach Stopped");
        assert!(stats.message_count > 0);
        assert_eq!(stats.peer_statistics.len(), peers.len());
        // Every peer's first-message share should be a valid fraction.
        for ps in &stats.peer_statistics {
            assert!((0.0..=1.0).contains(&ps.peer_first_message));
        }
    }

    // Direct port of go's `TestConnMonitor_BucketsPruning`.
    #[test]
    fn buckets_pruning_drops_only_expired_buckets() {
        let buckets_count = 100;
        let cur_time = 1_700_000_000_000_000_000i64;

        for i in 0..buckets_count {
            let mut mon = ConnectionPerformanceMonitor::new(&[Tag::AgreementVote]);
            for j in 0..buckets_count {
                if j < i {
                    mon.push_test_bucket(cur_time - 1);
                } else {
                    mon.push_test_bucket(cur_time + 1);
                }
            }
            mon.prune_old_messages(cur_time + PM_MAX_MESSAGE_WAIT_TIME);
            assert_eq!(
                mon.pending_bucket_count(),
                buckets_count - i,
                "iteration {i}: expected {} buckets to survive",
                buckets_count - i
            );
        }

        for i in 0..buckets_count {
            let mut mon = ConnectionPerformanceMonitor::new(&[Tag::AgreementVote]);
            for j in 0..buckets_count {
                mon.push_test_bucket(cur_time + j as i64);
            }
            mon.prune_old_messages(cur_time + PM_MAX_MESSAGE_WAIT_TIME + (i as i64 - 1));
            assert_eq!(
                mon.pending_bucket_count(),
                buckets_count - i,
                "iteration {i}: expected {} buckets to survive",
                buckets_count - i
            );
        }
    }

    #[test]
    fn compare_peers_matches_go_semantics() {
        let peers = vec!["a".to_string(), "b".to_string()];
        let mut mon = ConnectionPerformanceMonitor::new(&[Tag::AgreementVote]);
        mon.reset(&peers, 0);

        assert!(mon.compare_peers(&["a".to_string(), "b".to_string()]));
        assert!(mon.compare_peers(&["b".to_string(), "a".to_string()])); // order-insensitive
        assert!(!mon.compare_peers(&["a".to_string()])); // subset
        assert!(!mon.compare_peers(&["a".to_string(), "c".to_string()])); // different peer
    }

    #[test]
    fn get_peers_statistics_none_until_stopped() {
        let peers = vec!["a".to_string()];
        let mut mon = ConnectionPerformanceMonitor::new(&[Tag::AgreementVote]);
        mon.reset(&peers, 0);
        assert!(mon.get_peers_statistics().is_none());
    }

    // Direct port of go's `TestNetworkAdvanceMonitor`.
    #[test]
    fn network_advance_monitor_tracks_recent_progress() {
        let mut m = NetworkAdvanceMonitor::new();
        assert!(m.last_advanced_within(Duration::from_millis(500)));

        std::thread::sleep(Duration::from_millis(50));
        // Still within a generous window.
        assert!(m.last_advanced_within(Duration::from_secs(2)));

        m.update_last_advance();
        assert!(m.last_advanced_within(Duration::from_millis(500)));
    }

    // Small test-only extension so the stage-timing test can clone
    // synthetic messages while bumping `received_at` (`IncomingMessage`
    // doesn't derive `Clone` purely for this need elsewhere in the crate).
    trait CloneForTest {
        fn clone_for_test(&self) -> Self;
    }
    impl CloneForTest for IncomingMessage {
        fn clone_for_test(&self) -> Self {
            IncomingMessage {
                tag: self.tag,
                data: self.data.clone(),
                sender: self.sender.clone(),
                received_at: self.received_at,
                peer: self.peer.clone(),
            }
        }
    }
}
