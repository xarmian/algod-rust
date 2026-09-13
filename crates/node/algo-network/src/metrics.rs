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

//! Per-wire-tag byte/message metrics counters (issue #1425).
//!
//! Go's `network/metrics.go` declares a family of `*metrics.TagCounter`
//! instances (`util/metrics/tagcounter.go`) for the classic WS transport:
//! `networkSentBytesByTag`, `networkReceivedBytesByTag`,
//! `networkReceivedUncompressedBytesByTag`, `networkMessageSentByTag`,
//! `networkMessageReceivedByTag` — each a bounded-cardinality, per-tag
//! Prometheus-style counter (`algod_network_sent_bytes_{TAG}` etc.) built via
//! `metrics.NewTagCounterFiltered(rootName, desc, tagStringList, "UNK")`:
//! only tags in `tagStringList` (go's `protocol.TagList`, i.e. the *active*
//! tag set) get their own bucket; any other tag folds into a shared `"UNK"`
//! bucket rather than growing an unbounded metric-series label set. Go's
//! `TestTagCounterFiltering` (`network/wsPeer_test.go`) pins exactly this
//! property: adding a value under an unrecognized tag makes the rendered
//! metric text contain the `_UNK` series and never a series named after the
//! unrecognized tag itself.
//!
//! `algod-rust`'s [`Tag`] enum is a closed, compile-time-known set (mirroring
//! go's `protocol.Tag` values), and [`Tag::ACTIVE_TAGS`] is exactly go's
//! `protocol.TagList` allowlist — so unlike `algo_p2p::metrics::
//! GossipsubMetrics` (an open-ended `BTreeMap` keyed by arbitrary topic
//! strings) or `agreement_network::AgreementMessageCounters` (a fixed
//! 3-element array with no fallback bucket, since its 3 message types are
//! the only ones that can ever occur), [`TagCounter`] here needs exactly:
//! one atomic per [`Tag::ACTIVE_TAGS`] entry, plus one fallback atomic for
//! everything else (a deprecated tag like `pi`/`pj`, which go's `TagList`
//! also excludes). This mirrors go's design precisely while staying
//! allocation-free and lock-free on the hot path, following the same
//! fixed-array pattern `AgreementMessageCounters` already established in
//! this crate.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::tag::Tag;

/// Number of tags in [`Tag::ACTIVE_TAGS`] — go's `protocol.TagList`/
/// `tagStringList` allowlist.
const NUM_ACTIVE_TAGS: usize = Tag::ACTIVE_TAGS.len();

/// A bounded-cardinality, per-[`Tag`] counter with a shared fallback bucket
/// for any tag not in [`Tag::ACTIVE_TAGS`].
///
/// Mirrors go's `metrics.TagCounter` as constructed by
/// `metrics.NewTagCounterFiltered(name, desc, tagStringList, "UNK")`:
/// `Add(tag, val)` increments `tag`'s own bucket if `tag` is on the
/// allowlist, otherwise increments the fallback ("UNK") bucket instead of
/// creating a new, unbounded series.
#[derive(Debug, Default)]
pub struct TagCounter {
    per_tag: [AtomicU64; NUM_ACTIVE_TAGS],
    /// Fallback bucket for any tag not in [`Tag::ACTIVE_TAGS`]. Go: the
    /// `"UNK"` bucket.
    unknown: AtomicU64,
}

impl TagCounter {
    /// A fresh, all-zero counter set.
    pub fn new() -> Self {
        Self::default()
    }

    fn index_of(tag: Tag) -> Option<usize> {
        Tag::ACTIVE_TAGS.iter().position(|&t| t == tag)
    }

    /// `t[tag] += val`. Go: `TagCounter.Add(tag, val)`.
    ///
    /// Increments `tag`'s own bucket if `tag` is in [`Tag::ACTIVE_TAGS`];
    /// otherwise increments the shared fallback ("UNK") bucket. A deprecated
    /// tag (`pi`/`pj`) is not in `ACTIVE_TAGS` and so folds into the
    /// fallback bucket, exactly as it would in go (`protocol.TagList` does
    /// not include `DeprecatedTagList`).
    pub fn add(&self, tag: Tag, val: u64) {
        match Self::index_of(tag) {
            Some(i) => {
                self.per_tag[i].fetch_add(val, Ordering::Relaxed);
            }
            None => {
                self.unknown.fetch_add(val, Ordering::Relaxed);
            }
        }
    }

    /// Current count for `tag`'s own bucket. Zero for a tag that has never
    /// had a value added, or that is not in [`Tag::ACTIVE_TAGS`] (use
    /// [`Self::unknown`] for the fallback bucket's count instead).
    pub fn count(&self, tag: Tag) -> u64 {
        Self::index_of(tag)
            .map(|i| self.per_tag[i].load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Current count in the shared fallback ("UNK") bucket.
    pub fn unknown(&self) -> u64 {
        self.unknown.load(Ordering::Relaxed)
    }

    /// Render as Prometheus text exposition format: one series per touched
    /// tag bucket (`{metric_prefix}_{TAG}`), plus `{metric_prefix}_UNK` for
    /// the fallback bucket if it is nonzero. Matches go's `metrics.TagCounter
    /// .WriteMetric`'s naming convention of substituting the tag into the
    /// metric name itself, not as a label (see `algo_p2p::metrics::
    /// GossipsubMetrics::to_prometheus_text` for the same established
    /// pattern in this workspace).
    pub fn to_prometheus_text(&self, metric_prefix: &str, help: &str) -> String {
        let mut out = String::with_capacity(256);
        for (i, tag) in Tag::ACTIVE_TAGS.iter().enumerate() {
            let count = self.per_tag[i].load(Ordering::Relaxed);
            if count == 0 {
                continue;
            }
            let name = format!("{metric_prefix}_{tag}");
            out.push_str(&format!(
                "# HELP {name} {}\n# TYPE {name} counter\n{name} {count}\n",
                help.replace("{TAG}", tag.as_str())
            ));
        }
        let unk = self.unknown.load(Ordering::Relaxed);
        if unk != 0 {
            let name = format!("{metric_prefix}_UNK");
            out.push_str(&format!(
                "# HELP {name} {}\n# TYPE {name} counter\n{name} {unk}\n",
                help.replace("{TAG}", "UNK")
            ));
        }
        out
    }
}

/// The classic WS transport's full family of per-tag traffic counters
/// (issue #1425).
///
/// Mirrors go's `network/metrics.go` package-level `*metrics.TagCounter`
/// vars for the non-P2P transport:
///
/// | Field                        | Go variable                              |
/// |-------------------------------|------------------------------------------|
/// | [`sent_bytes`]                | `networkSentBytesByTag`                   |
/// | [`received_bytes`]            | `networkReceivedBytesByTag`               |
/// | [`received_uncompressed_bytes`] | `networkReceivedUncompressedBytesByTag` |
/// | [`message_sent`]              | `networkMessageSentByTag`                 |
/// | [`message_received`]          | `networkMessageReceivedByTag`             |
///
/// [`sent_bytes`]: Self::sent_bytes
/// [`received_bytes`]: Self::received_bytes
/// [`received_uncompressed_bytes`]: Self::received_uncompressed_bytes
/// [`message_sent`]: Self::message_sent
/// [`message_received`]: Self::message_received
///
/// A single instance is meant to be shared (via `Arc`) across every peer of
/// one [`crate::ws_network::WebsocketNetwork`] — go's counters are process-
/// global, aggregating traffic across all peers, not per-connection.
#[derive(Debug, Default)]
pub struct NetworkTagMetrics {
    sent_bytes: TagCounter,
    received_bytes: TagCounter,
    received_uncompressed_bytes: TagCounter,
    message_sent: TagCounter,
    message_received: TagCounter,
}

impl NetworkTagMetrics {
    /// A fresh, all-zero metrics set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `len` bytes sent for `tag`. Go:
    /// `networkSentBytesByTag.Add(string(tag), uint64(len(dataToSend)))`.
    pub fn record_sent(&self, tag: Tag, len: u64) {
        self.sent_bytes.add(tag, len);
        self.message_sent.add(tag, 1);
    }

    /// Record `len` bytes received (on-wire, pre-decompression) for `tag`.
    /// Go: `networkReceivedBytesByTag.Add(string(tag[:]), ...)`.
    pub fn record_received(&self, tag: Tag, len: u64) {
        self.received_bytes.add(tag, len);
        self.message_received.add(tag, 1);
    }

    /// Record `len` bytes after decompression for `tag`. Go:
    /// `networkReceivedUncompressedBytesByTag.Add(string(msg.Tag), ...)`.
    pub fn record_received_uncompressed(&self, tag: Tag, len: u64) {
        self.received_uncompressed_bytes.add(tag, len);
    }

    /// Bytes sent for `tag`'s own bucket.
    pub fn sent_bytes(&self, tag: Tag) -> u64 {
        self.sent_bytes.count(tag)
    }

    /// Bytes received for `tag`'s own bucket.
    pub fn received_bytes(&self, tag: Tag) -> u64 {
        self.received_bytes.count(tag)
    }

    /// Post-decompression bytes received for `tag`'s own bucket.
    pub fn received_uncompressed_bytes(&self, tag: Tag) -> u64 {
        self.received_uncompressed_bytes.count(tag)
    }

    /// Messages sent for `tag`'s own bucket.
    pub fn messages_sent(&self, tag: Tag) -> u64 {
        self.message_sent.count(tag)
    }

    /// Messages received for `tag`'s own bucket.
    pub fn messages_received(&self, tag: Tag) -> u64 {
        self.message_received.count(tag)
    }

    /// Fallback ("UNK") bucket, sent-bytes count. Nonzero only if a message
    /// carrying a tag outside [`Tag::ACTIVE_TAGS`] (e.g. a deprecated `pi`/
    /// `pj` tag) was ever sent.
    pub fn unknown_sent_bytes(&self) -> u64 {
        self.sent_bytes.unknown()
    }

    /// Fallback ("UNK") bucket, received-bytes count.
    pub fn unknown_received_bytes(&self) -> u64 {
        self.received_bytes.unknown()
    }

    /// Render the full family as Prometheus text exposition format.
    pub fn to_prometheus_text(&self) -> String {
        let mut out = String::with_capacity(1024);
        out.push_str(&self.sent_bytes.to_prometheus_text(
            "algod_network_sent_bytes",
            "Number of bytes that were sent over the network for {TAG} messages",
        ));
        out.push_str(&self.received_bytes.to_prometheus_text(
            "algod_network_received_bytes",
            "Number of bytes that were received from the network for {TAG} messages",
        ));
        out.push_str(&self.received_uncompressed_bytes.to_prometheus_text(
            "algod_network_received_uncompressed_bytes",
            "Number of bytes after decompression that were received from the network for {TAG} messages",
        ));
        out.push_str(&self.message_sent.to_prometheus_text(
            "algod_network_message_sent",
            "Number of complete messages that were sent to the network for {TAG} messages",
        ));
        out.push_str(&self.message_received.to_prometheus_text(
            "algod_network_message_received",
            "Number of complete messages that were received from the network for {TAG} messages",
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // TagCounter — bounded-cardinality / fallback-bucket semantics
    // (ports go's `TestTagCounterFiltering`, `network/wsPeer_test.go`)
    // -----------------------------------------------------------------

    #[test]
    fn known_tag_increments_its_own_bucket() {
        let tc = TagCounter::new();
        tc.add(Tag::Transaction, 1);
        tc.add(Tag::Transaction, 41);
        assert_eq!(tc.count(Tag::Transaction), 42);
        assert_eq!(tc.unknown(), 0);
    }

    /// Go's `TestTagCounterFiltering` sends a value under an unrecognized
    /// tag ("TEST_TAG") and asserts the rendered metric text contains the
    /// `_UNK` series and never a series literally named after the
    /// unrecognized tag. This crate's `Tag` enum has no open-ended
    /// "unrecognized string" case for an *active* tag (every active tag is
    /// a closed enum variant), so the equivalent unrecognized-tag case is a
    /// deprecated tag (`pi`/`pj`) — present in the wire protocol's tag
    /// space but deliberately excluded from `Tag::ACTIVE_TAGS`/go's
    /// `protocol.TagList`, exactly like go's test tag being outside
    /// `tagStringList`.
    #[test]
    fn unrecognized_tag_increments_fallback_bucket_not_its_own() {
        let tc = TagCounter::new();
        tc.add(Tag::PingDeprecated, 7);

        assert_eq!(tc.unknown(), 7);
        // No bucket exists for a non-active tag; count() reports 0 for it
        // rather than aliasing onto the fallback bucket's value.
        assert_eq!(tc.count(Tag::PingDeprecated), 0);

        let text = tc.to_prometheus_text("algod_network_sent_bytes", "help {TAG}");
        assert!(text.contains("algod_network_sent_bytes_UNK 7"));
        assert!(!text.contains("algod_network_sent_bytes_pi"));
    }

    #[test]
    fn multiple_tags_and_fallback_are_independent() {
        let tc = TagCounter::new();
        tc.add(Tag::Transaction, 10);
        tc.add(Tag::AgreementVote, 20);
        tc.add(Tag::PingDeprecated, 5);
        tc.add(Tag::PingReplyDeprecated, 3);

        assert_eq!(tc.count(Tag::Transaction), 10);
        assert_eq!(tc.count(Tag::AgreementVote), 20);
        assert_eq!(tc.unknown(), 8);
    }

    #[test]
    fn prometheus_text_omits_untouched_tags() {
        let tc = TagCounter::new();
        tc.add(Tag::Transaction, 1);
        let text = tc.to_prometheus_text("m", "d {TAG}");
        assert!(text.contains("m_TX 1"));
        assert!(!text.contains("m_AV"));
        assert!(!text.contains("m_UNK"));
    }

    // -----------------------------------------------------------------
    // NetworkTagMetrics — bundled sent/received bytes+messages family
    // -----------------------------------------------------------------

    #[test]
    fn record_sent_increments_bytes_and_message_count() {
        let m = NetworkTagMetrics::new();
        m.record_sent(Tag::Transaction, 100);
        m.record_sent(Tag::Transaction, 50);

        assert_eq!(m.sent_bytes(Tag::Transaction), 150);
        assert_eq!(m.messages_sent(Tag::Transaction), 2);
        assert_eq!(m.sent_bytes(Tag::AgreementVote), 0);
    }

    #[test]
    fn record_received_increments_bytes_and_message_count() {
        let m = NetworkTagMetrics::new();
        m.record_received(Tag::AgreementVote, 30);

        assert_eq!(m.received_bytes(Tag::AgreementVote), 30);
        assert_eq!(m.messages_received(Tag::AgreementVote), 1);
    }

    #[test]
    fn record_received_uncompressed_is_tracked_separately() {
        let m = NetworkTagMetrics::new();
        m.record_received(Tag::ProposalPayload, 20); // on-wire, compressed
        m.record_received_uncompressed(Tag::ProposalPayload, 500); // post-decompress

        assert_eq!(m.received_bytes(Tag::ProposalPayload), 20);
        assert_eq!(m.received_uncompressed_bytes(Tag::ProposalPayload), 500);
    }

    #[test]
    fn deprecated_tag_traffic_folds_into_unknown_bucket() {
        let m = NetworkTagMetrics::new();
        m.record_sent(Tag::PingDeprecated, 4);
        m.record_received(Tag::PingReplyDeprecated, 9);

        assert_eq!(m.unknown_sent_bytes(), 4);
        assert_eq!(m.unknown_received_bytes(), 9);
    }

    #[test]
    fn prometheus_text_includes_tag_in_series_name_not_as_label() {
        let m = NetworkTagMetrics::new();
        m.record_sent(Tag::Transaction, 42);
        m.record_received(Tag::Transaction, 9);
        let text = m.to_prometheus_text();

        assert!(text.contains("algod_network_sent_bytes_TX 42\n"));
        assert!(text.contains("algod_network_message_sent_TX 1\n"));
        assert!(text.contains("algod_network_received_bytes_TX 9\n"));
        assert!(text.contains("algod_network_message_received_TX 1\n"));
        assert!(!text.contains("tag=\""));
    }

    #[test]
    fn prometheus_text_empty_metrics_emits_no_series() {
        let m = NetworkTagMetrics::new();
        assert_eq!(m.to_prometheus_text(), "");
    }
}
