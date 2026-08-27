//! GossipSub topic naming for algod-rust's P2P block/vote/tx propagation.
//!
//! Mirrors go-algorand's `network/p2p/pubsub.go` topic-naming convention:
//! `"algo" + <2-byte protocol tag> + <2-digit version>`. Go's own comment on
//! `TXTopicName` calls out the choice deliberately ("8 bytes const string
//! require a single x86-64 CMPQ instruction"), so the same fixed-width shape
//! is reused here.
//!
//! As of `v4.7.3-stable`, go-algorand's `gossipSubTags` map
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
use libp2p::gossipsub::IdentTopic;

/// GossipSub topic name for transactions (`TX`).
///
/// Byte-for-byte identical to go-algorand's `network/p2p.TXTopicName` — this
/// is the one topic go-algorand v4.7.3-stable itself gossips over pubsub, so
/// this exact string is required for wire-level interop with a real
/// go-algorand P2P peer.
pub const TX_TOPIC: &str = "algotx01";

/// GossipSub topic name for agreement votes (`AV`).
///
/// Not wired up by go-algorand v4.7.3-stable's own `gossipSubTags` (votes
/// still travel over the per-peer stream protocol there) — see this
/// module's doc comment.
pub const AGREEMENT_VOTE_TOPIC: &str = "algoav01";

/// GossipSub topic name for block proposal payloads (`PP`).
///
/// Not wired up by go-algorand v4.7.3-stable's own `gossipSubTags` — see
/// this module's doc comment.
pub const PROPOSAL_PAYLOAD_TOPIC: &str = "algopp01";

/// GossipSub topic name for certified vote bundles (`VB`).
///
/// Not wired up by go-algorand v4.7.3-stable's own `gossipSubTags` — see
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
}
