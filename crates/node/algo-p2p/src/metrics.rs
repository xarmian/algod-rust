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

//! Per-Algorand-tag gossipsub metrics (issue #1085).
//!
//! Go-algorand wires a `pubsub.RawTracer` (`network/metrics.go`'s
//! `pubsubMetricsTracer`) into its `go-libp2p-pubsub` instance, whose
//! `SendRPC`/`RecvRPC` hooks map each published/received gossipsub RPC's
//! topic back to an Algorand protocol tag (`gossipSubTags`,
//! `network/p2pNetwork.go` — currently just `protocol.TxnTag` →
//! `p2p.TXTopicName`, the only tag go-algorand v5.0.0-stable relays over
//! gossipsub) and increments per-tag Prometheus counters
//! (`algod_network_p2p_{sent,received}_bytes_{TAG}`,
//! `algod_network_p2p_message_{sent,received}_{TAG}`).
//!
//! `rust-libp2p`'s `gossipsub` crate has no equivalent tracer hook exposed
//! on its public API: `Behaviour::new_with_metrics` takes a
//! `prometheus_client::registry::Registry` and records metrics keyed by
//! [`libp2p::gossipsub::TopicHash`] using the topic string as an opaque
//! label — not by Algorand tag — and would pull in a new `prometheus-client`
//! dependency purely to reshape data this crate could track itself in a few
//! dozen lines (this repo's Prometheus exporter is hand-rolled elsewhere for
//! exactly this reason — see `algo-agreement::metrics`). So this module
//! takes the lighter-weight path the issue calls out as acceptable:
//! [`crate::host::P2pHost`] records a count/byte-count pair itself at the
//! two points where it already has a topic name and a payload size in hand
//! — [`crate::host::P2pHost::gossipsub_publish`] (outgoing) and
//! [`crate::host::P2pHost::next_event`]'s handling of
//! `gossipsub::Event::Message` (incoming) — deriving the Algorand tag from
//! the topic name via [`crate::pubsub::tag_code_for_topic_name`].

use std::collections::BTreeMap;

/// Message/byte counts recorded for one direction (sent or received) of one
/// Algorand protocol tag's gossipsub traffic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GossipsubTagCounts {
    /// Number of complete gossipsub messages for this tag.
    ///
    /// Go: `networkP2PMessageSentByTag`/`networkP2PMessageReceivedByTag`.
    pub messages: u64,
    /// Total payload bytes across those messages.
    ///
    /// Go: `networkP2PSentBytesByTag`/`networkP2PReceivedBytesByTag`.
    pub bytes: u64,
}

impl GossipsubTagCounts {
    fn record(&mut self, payload_len: usize) {
        self.messages += 1;
        self.bytes += payload_len as u64;
    }
}

/// Per-tag gossipsub send/receive counters for one [`crate::host::P2pHost`].
///
/// Only tags this crate actually maps a gossipsub topic for
/// ([`crate::pubsub::tag_code_for_topic_name`]) are ever recorded — an
/// unrecognized topic (e.g. from a future protocol version, or a peer
/// publishing to something this host never subscribed to) is silently not
/// counted, mirroring go's `metrics.NewTagCounterFiltered` behavior of
/// bucketing anything outside its known tag list under `"UNK"` rather than
/// panicking or growing an unbounded label set — this crate simply omits
/// the "UNK" bucket since no code path here observes an unrecognized topic
/// carrying gossip traffic that would need counting at all.
#[derive(Debug, Default)]
pub struct GossipsubMetrics {
    sent: BTreeMap<&'static str, GossipsubTagCounts>,
    received: BTreeMap<&'static str, GossipsubTagCounts>,
}

impl GossipsubMetrics {
    /// A fresh, all-zero counter set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one outgoing gossipsub message of `payload_len` bytes for
    /// `tag`. Go: `pubsubMetricsTracer.SendRPC`.
    pub(crate) fn record_sent(&mut self, tag: &'static str, payload_len: usize) {
        self.sent.entry(tag).or_default().record(payload_len);
    }

    /// Record one incoming gossipsub message of `payload_len` bytes for
    /// `tag`. Go: `pubsubMetricsTracer.RecvRPC`.
    pub(crate) fn record_received(&mut self, tag: &'static str, payload_len: usize) {
        self.received.entry(tag).or_default().record(payload_len);
    }

    /// Counts recorded for outgoing messages carrying `tag` (e.g. `"TX"`).
    /// Zero (not absent) for a tag nothing has been sent for yet.
    pub fn sent_for_tag(&self, tag: &str) -> GossipsubTagCounts {
        self.sent.get(tag).copied().unwrap_or_default()
    }

    /// Counts recorded for incoming messages carrying `tag` (e.g. `"TX"`).
    /// Zero (not absent) for a tag nothing has been received for yet.
    pub fn received_for_tag(&self, tag: &str) -> GossipsubTagCounts {
        self.received.get(tag).copied().unwrap_or_default()
    }

    /// Render as Prometheus text exposition format, one metric family per
    /// go-algorand series (`algod_network_p2p_sent_bytes_{TAG}` etc.),
    /// substituting the literal tag into the metric name exactly as go's
    /// `metrics.TagCounter` does — not as a label — so a scraper already
    /// configured for go-algorand's P2P metrics recognizes the same series
    /// names from an algod-rust P2P node.
    ///
    /// Hand-written for the same reason as
    /// `algo_agreement::metrics::ParticipationSnapshot::to_prometheus_text`:
    /// a couple of metric families is not worth a `prometheus` crate
    /// dependency.
    pub fn to_prometheus_text(&self) -> String {
        let mut out = String::with_capacity(512);
        for (metric, help, direction) in [
            (
                "algod_network_p2p_sent_bytes",
                "Number of bytes that were sent over the network for {TAG} messages",
                &self.sent,
            ),
            (
                "algod_network_p2p_received_bytes",
                "Number of bytes that were received from the network for {TAG} messages",
                &self.received,
            ),
        ] {
            for (tag, counts) in direction {
                out.push_str(&format!(
                    "# HELP {metric}_{tag} {}\n# TYPE {metric}_{tag} counter\n{metric}_{tag} {}\n",
                    help.replace("{TAG}", tag),
                    counts.bytes
                ));
            }
        }
        for (metric, help, direction) in [
            (
                "algod_network_p2p_message_sent",
                "Number of complete messages that were sent to the network for {TAG} messages",
                &self.sent,
            ),
            (
                "algod_network_p2p_message_received",
                "Number of complete messages that were received from the network for {TAG} messages",
                &self.received,
            ),
        ] {
            for (tag, counts) in direction {
                out.push_str(&format!(
                    "# HELP {metric}_{tag} {}\n# TYPE {metric}_{tag} counter\n{metric}_{tag} {}\n",
                    help.replace("{TAG}", tag),
                    counts.messages
                ));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_sent_bytes_and_messages_per_tag() {
        let mut m = GossipsubMetrics::new();
        m.record_sent("TX", 10);
        m.record_sent("TX", 20);
        m.record_sent("PP", 5);

        assert_eq!(
            m.sent_for_tag("TX"),
            GossipsubTagCounts {
                messages: 2,
                bytes: 30
            }
        );
        assert_eq!(
            m.sent_for_tag("PP"),
            GossipsubTagCounts {
                messages: 1,
                bytes: 5
            }
        );
        assert_eq!(m.sent_for_tag("AV"), GossipsubTagCounts::default());
    }

    #[test]
    fn records_received_bytes_and_messages_per_tag_independent_of_sent() {
        let mut m = GossipsubMetrics::new();
        m.record_sent("TX", 100);
        m.record_received("TX", 7);

        assert_eq!(
            m.received_for_tag("TX"),
            GossipsubTagCounts {
                messages: 1,
                bytes: 7
            }
        );
        assert_eq!(
            m.sent_for_tag("TX"),
            GossipsubTagCounts {
                messages: 1,
                bytes: 100
            }
        );
    }

    #[test]
    fn prometheus_text_includes_tag_in_metric_name_not_as_label() {
        let mut m = GossipsubMetrics::new();
        m.record_sent("TX", 42);
        m.record_received("TX", 9);
        let text = m.to_prometheus_text();

        assert!(text.contains("algod_network_p2p_sent_bytes_TX 42\n"));
        assert!(text.contains("algod_network_p2p_message_sent_TX 1\n"));
        assert!(text.contains("algod_network_p2p_received_bytes_TX 9\n"));
        assert!(text.contains("algod_network_p2p_message_received_TX 1\n"));
        // Go substitutes the tag literally into the series name, not a label.
        assert!(!text.contains("tag=\""));
    }

    #[test]
    fn prometheus_text_empty_metrics_emits_no_series() {
        let m = GossipsubMetrics::new();
        assert_eq!(m.to_prometheus_text(), "");
    }
}
