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

//! GossipSub topic naming for algod-rust's P2P block/vote/tx propagation.
//!
//! Mirrors go-algorand's `network/p2p/pubsub.go` topic-naming convention:
//! `"algo" + <2-byte protocol tag> + <2-digit version>`. Go's own comment on
//! `TXTopicName` calls out the choice deliberately ("8 bytes const string
//! require a single x86-64 CMPQ instruction"), so the same fixed-width shape
//! is reused here.
//!
//! As of `v5.0.0-stable`, go-algorand's `gossipSubTags` map
//! (`network/p2pNetwork.go`) wires up gossipsub for exactly one tag —
//! `protocol.TxnTag` → [`TX_TOPIC`] (`"algotx01"`, byte-for-byte identical to
//! go's `p2p.TXTopicName`, for real interop with a go-algorand P2P peer on
//! that topic). Blocks (proposal payloads) and votes/certified-vote-bundles
//! still flow over go-algorand's per-peer stream protocol even in P2P mode
//! — they are not yet gossipsub topics upstream. The topics below for those
//! tags ([`AGREEMENT_VOTE_TOPIC`], [`PROPOSAL_PAYLOAD_TOPIC`],
//! [`VOTE_BUNDLE_TOPIC`]) extend go's own naming convention so that a future
//! go-algorand version adding them (or a later algod-rust integration,
//! #542) has a ready-made, convention-consistent name to converge on; they
//! are algod-rust-only today and are not expected to be understood by a
//! current go-algorand P2P node.
use std::time::Duration;

use libp2p::gossipsub::IdentTopic;

/// GossipSub topic name for transactions (`TX`).
///
/// Byte-for-byte identical to go-algorand's `network/p2p.TXTopicName` — this
/// is the one topic go-algorand v5.0.0-stable itself gossips over pubsub, so
/// this exact string is required for wire-level interop with a real
/// go-algorand P2P peer.
pub const TX_TOPIC: &str = "algotx01";

/// GossipSub topic name for agreement votes (`AV`).
///
/// Not wired up by go-algorand v5.0.0-stable's own `gossipSubTags` (votes
/// still travel over the per-peer stream protocol there) — see this
/// module's doc comment.
pub const AGREEMENT_VOTE_TOPIC: &str = "algoav01";

/// GossipSub topic name for block proposal payloads (`PP`).
///
/// Not wired up by go-algorand v5.0.0-stable's own `gossipSubTags` — see
/// this module's doc comment.
pub const PROPOSAL_PAYLOAD_TOPIC: &str = "algopp01";

/// GossipSub topic name for certified vote bundles (`VB`).
///
/// Not wired up by go-algorand v5.0.0-stable's own `gossipSubTags` — see
/// this module's doc comment.
pub const VOTE_BUNDLE_TOPIC: &str = "algovb01";

/// All topics this crate knows how to name, for iteration (e.g. subscribing
/// to every propagation topic at node startup).
pub const ALL_TOPICS: [&str; 4] = [
    TX_TOPIC,
    AGREEMENT_VOTE_TOPIC,
    PROPOSAL_PAYLOAD_TOPIC,
    VOTE_BUNDLE_TOPIC,
];

/// Derive the algod-rust/go-algorand gossipsub topic name for a 2-character
/// ASCII protocol tag code (e.g. `"TX"`, `"AV"`, `"PP"`, `"VB"` — matching
/// `algo-network::tag::Tag::as_str()`), following the `"algo" + tag + "01"`
/// convention documented on this module. Returns `None` for a tag code this
/// crate does not (yet) define a topic for.
///
/// This crate deliberately does not depend on `algo-network`'s `Tag` type
/// (that dependency direction is inverted — `algo-network` will depend on
/// `algo-p2p`, not the other way around — see #542), so callers pass the
/// tag's 2-character wire code directly.
pub fn topic_name_for_tag_code(tag_code: &str) -> Option<&'static str> {
    match tag_code {
        "TX" => Some(TX_TOPIC),
        "AV" => Some(AGREEMENT_VOTE_TOPIC),
        "PP" => Some(PROPOSAL_PAYLOAD_TOPIC),
        "VB" => Some(VOTE_BUNDLE_TOPIC),
        _ => None,
    }
}

/// Build the [`IdentTopic`] for a topic name string.
///
/// `IdentTopic` (identity-hashed topic) is what go-algorand's
/// `go-libp2p-pubsub` uses too (topic names are the hash, not the input to
/// a hash function) — required so `TopicHash::as_str()` on the receive side
/// recovers the original topic name rather than an opaque digest.
pub fn ident_topic(topic_name: &str) -> IdentTopic {
    IdentTopic::new(topic_name)
}

/// Gossipsub mesh-degree parameters derived from a node's number of
/// outgoing connections, mirroring go-libp2p-pubsub's `GossipSubParams`
/// field names (`D`, `Dlo`, `Dscore`, `Dout`, `Dhi`, `Dlazy`) so this
/// struct's fields map directly onto go's own.
///
/// Go: `network/p2p/pubsub.go` `deriveAlgorandGossipSubParams`'s D-family
/// output (the remaining fields it sets — `HistoryLength`, `GossipFactor`,
/// `DirectConnectInitialDelay`, `IWantFollowupTime` — are fixed constants
/// independent of `num_outgoing_conns`, included here for the same reason
/// go sets them explicitly: to document the intended values even though
/// only the D-family actually varies with `num_outgoing_conns`).
///
/// A caller applying this to a live [`gossipsub::ConfigBuilder`] maps each
/// field as follows (`rust-libp2p`'s `libp2p-gossipsub` names these
/// differently from the `go-libp2p-pubsub` spec-derived names above):
/// `d` → `mesh_n`, `dlo` → `mesh_n_low`, `dhi` → `mesh_n_high`, `dscore` →
/// `retain_scores`, `dout` → `mesh_outbound_min`, `dlazy` →
/// `gossip_lazy`, `history_length` → `history_length`, `gossip_factor` →
/// `gossip_factor`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GossipsubMeshParams {
    /// Target mesh degree. Go: `D`.
    pub d: usize,
    /// Low water mark for mesh degree (triggers GRAFT to top back up). Go:
    /// `Dlo`.
    pub dlo: usize,
    /// Minimum number of mesh peers kept purely on score (rather than
    /// pruned to make room for outbound-min/random peers). Go: `Dscore`.
    pub dscore: usize,
    /// Minimum number of *outbound* mesh connections to maintain (defense
    /// against eclipse via inbound-only mesh peers). Go: `Dout`.
    pub dout: usize,
    /// High water mark for mesh degree (triggers PRUNE to trim down). Go:
    /// `Dhi`.
    pub dhi: usize,
    /// Number of peers to gossip IHAVE to outside the mesh, per heartbeat.
    /// Go: `Dlazy`.
    pub dlazy: usize,
    /// Number of past heartbeats to remember message IDs for. Go:
    /// `HistoryLength`.
    pub history_length: usize,
    /// Fraction of non-mesh peers, chosen at random, to also emit gossip
    /// to (on top of `dlazy`). Go: `GossipFactor`.
    pub gossip_factor: f64,
}

/// Derive gossipsub mesh-degree parameters from a node's number of
/// outgoing (mesh-eligible) connections.
///
/// Go: `network/p2p/pubsub.go` `deriveAlgorandGossipSubParams`. Comment
/// from go's source, reproduced verbatim: "derives the gossip sub
/// parameters from the cfg.GossipFanout value by using the same
/// proportions as pubsub defaults". The three regimes go implements:
/// - `num_outgoing_conns <= 0`: no outgoing connections — every D-family
///   value is `0` (no mesh at all).
/// - `1..=4`: hardcoded minimal values satisfying `go-libp2p-pubsub`'s
///   validation constraints (`Dout < Dlo && Dout < D/2`).
/// - `5..=11`: scaled proportionally to `num_outgoing_conns`, preserving
///   the same ratios as go-libp2p-pubsub's own defaults (`D/n ≈ 2/3`,
///   `Dlo/D = Dscore/D = 3/4`, `Dout/D = 3/8`, `Dhi = Dlazy = n`).
/// - `>= 12`: capped to the "large overlay" defaults go sets up front
///   (`D=8, Dscore=6, Dout=3, Dlo=6, Dhi=12, Dlazy=12`).
pub fn derive_algorand_gossipsub_params(num_outgoing_conns: i64) -> GossipsubMeshParams {
    // go's `params := pubsub.DefaultGossipSubParams()` followed by the
    // "configure larger overlay parameters" block — the values below are
    // that block's literal constants, used verbatim for the >=12 case and
    // as the starting point documented (but not read) by the other cases.
    const HISTORY_LENGTH: usize = 10;
    const GOSSIP_FACTOR: f64 = 0.1;

    if num_outgoing_conns >= 12 {
        return GossipsubMeshParams {
            d: 8,
            dscore: 6,
            dout: 3,
            dlo: 6,
            dhi: 12,
            dlazy: 12,
            history_length: HISTORY_LENGTH,
            gossip_factor: GOSSIP_FACTOR,
        };
    }
    if num_outgoing_conns <= 0 {
        return GossipsubMeshParams {
            d: 0,
            dscore: 0,
            dout: 0,
            dlo: 0,
            dhi: 0,
            dlazy: 0,
            history_length: HISTORY_LENGTH,
            gossip_factor: GOSSIP_FACTOR,
        };
    }
    if num_outgoing_conns <= 4 {
        return GossipsubMeshParams {
            d: 4,
            dscore: 1,
            dout: 1,
            dlo: 2,
            dhi: 4,
            dlazy: 4,
            history_length: HISTORY_LENGTH,
            gossip_factor: GOSSIP_FACTOR,
        };
    }

    // 5..=11: scale proportionally, keeping the same ratios as the
    // defaults (see this function's doc comment).
    let n = num_outgoing_conns;
    let d = n - n / 3;
    GossipsubMeshParams {
        d: d as usize,
        dlo: (d * 3 / 4) as usize,
        dscore: (d * 3 / 4) as usize,
        dhi: n as usize,
        dlazy: n as usize,
        dout: (d * 3 / 8) as usize,
        history_length: HISTORY_LENGTH,
        gossip_factor: GOSSIP_FACTOR,
    }
}

/// `DirectConnectInitialDelay` go additionally sets on
/// `deriveAlgorandGossipSubParams`'s output — a fixed value independent
/// of `num_outgoing_conns`, so not part of [`GossipsubMeshParams`] (which
/// only carries fields the derivation logic actually varies or that a
/// caller building a full go-libp2p-pubsub-equivalent config needs
/// alongside them). Go: `network/p2p/pubsub.go`,
/// `params.DirectConnectInitialDelay = 30 * time.Second`.
pub const DIRECT_CONNECT_INITIAL_DELAY: Duration = Duration::from_secs(30);

/// `IWantFollowupTime` go additionally sets on
/// `deriveAlgorandGossipSubParams`'s output — see
/// [`DIRECT_CONNECT_INITIAL_DELAY`]'s doc comment for why this is a
/// separate constant rather than a [`GossipsubMeshParams`] field. Go:
/// `network/p2p/pubsub.go`, `params.IWantFollowupTime = 5 * time.Second`.
pub const IWANT_FOLLOWUP_TIME: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_topic_matches_go_exactly() {
        // go: `const TXTopicName = "algotx01"` (network/p2p/pubsub.go).
        assert_eq!(TX_TOPIC, "algotx01");
    }

    #[test]
    fn topics_follow_naming_convention() {
        for topic in ALL_TOPICS {
            assert_eq!(topic.len(), 8, "topic {topic} should be 8 bytes");
            assert!(
                topic.starts_with("algo"),
                "topic {topic} should start with algo"
            );
            assert!(
                topic.ends_with("01"),
                "topic {topic} should end with version 01"
            );
        }
    }

    #[test]
    fn topic_name_for_tag_code_known_tags() {
        assert_eq!(topic_name_for_tag_code("TX"), Some(TX_TOPIC));
        assert_eq!(topic_name_for_tag_code("AV"), Some(AGREEMENT_VOTE_TOPIC));
        assert_eq!(topic_name_for_tag_code("PP"), Some(PROPOSAL_PAYLOAD_TOPIC));
        assert_eq!(topic_name_for_tag_code("VB"), Some(VOTE_BUNDLE_TOPIC));
    }

    #[test]
    fn topic_name_for_tag_code_unknown_tag() {
        assert_eq!(topic_name_for_tag_code("MI"), None);
        assert_eq!(topic_name_for_tag_code(""), None);
    }

    #[test]
    fn ident_topic_hash_round_trips_topic_name() {
        // IdentTopic uses the identity hash, so the resulting TopicHash's
        // string form must be the topic name itself, unmodified — this is
        // what lets a receiver recover the topic name from a TopicHash on
        // an incoming message.
        let topic = ident_topic(TX_TOPIC);
        assert_eq!(topic.hash().as_str(), TX_TOPIC);
    }

    // --- derive_algorand_gossipsub_params (go: TestPubsub_GossipSubParams*) -

    #[test]
    fn gossipsub_params_basic() {
        // n, D, Dlo, Dscore, Dout, Dhi, Dlazy
        let expected = [
            (5, 4, 3, 3, 1, 5, 5),
            (6, 4, 3, 3, 1, 6, 6),
            (7, 5, 3, 3, 1, 7, 7),
            (8, 6, 4, 4, 2, 8, 8),
            (9, 6, 4, 4, 2, 9, 9),
            (10, 7, 5, 5, 2, 10, 10),
            (11, 8, 6, 6, 3, 11, 11),
            (12, 8, 6, 6, 3, 12, 12),
        ];

        for (n, d, dlo, dscore, dout, dhi, dlazy) in expected {
            let p = derive_algorand_gossipsub_params(n);
            assert_eq!(p.d, d, "n={n} D");
            assert_eq!(p.dlo, dlo, "n={n} Dlo");
            assert_eq!(p.dscore, dscore, "n={n} Dscore");
            assert_eq!(p.dout, dout, "n={n} Dout");
            assert_eq!(p.dhi, dhi, "n={n} Dhi");
            assert_eq!(p.dlazy, dlazy, "n={n} Dlazy");
        }
    }

    /// Verify libp2p gossipsub `validate()` constraints:
    /// 1. `Dlo <= D <= Dhi`
    /// 2. `Dscore <= Dhi`
    /// 3. `Dout < Dlo` (strict)
    /// 4. `Dout < D/2` (strict, integer division)
    #[test]
    fn gossipsub_params_validate_constraints() {
        for n in 1..=20 {
            let p = derive_algorand_gossipsub_params(n);
            assert!(p.dlo <= p.d, "n={n}: Dlo <= D");
            assert!(p.d <= p.dhi, "n={n}: D <= Dhi");
            assert!(p.dscore <= p.dhi, "n={n}: Dscore <= Dhi");
            assert!(p.dout < p.dlo, "n={n}: Dout < Dlo");
            assert!(p.dout < p.d / 2, "n={n}: Dout < D/2");
        }
    }

    #[test]
    fn gossipsub_params_edge_cases() {
        let p = derive_algorand_gossipsub_params(0);
        assert_eq!(
            (p.d, p.dlo, p.dscore, p.dout, p.dhi, p.dlazy),
            (0, 0, 0, 0, 0, 0)
        );

        for n in 1..=4 {
            let p = derive_algorand_gossipsub_params(n);
            assert_eq!(
                (p.d, p.dlo, p.dscore, p.dout, p.dhi, p.dlazy),
                (4, 2, 1, 1, 4, 4)
            );
        }

        for n in 12..=20 {
            let p = derive_algorand_gossipsub_params(n);
            assert_eq!(
                (p.d, p.dlo, p.dscore, p.dout, p.dhi, p.dlazy),
                (8, 6, 6, 3, 12, 12)
            );
        }
    }
}
