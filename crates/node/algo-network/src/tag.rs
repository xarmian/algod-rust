//! Protocol message tags.
//!
//! Each tag is a 2-byte ASCII identifier that marks the type of a WebSocket
//! message.  Tags and their per-tag size limits come directly from
//! `go-algorand/protocol/tags.go` (v4.6.0-stable).

/// Length of every protocol tag in bytes.
pub const TAG_LENGTH: usize = 2;

/// Global maximum message length (matches `network.MaxMessageLength` in Go).
pub const MAX_MESSAGE_LENGTH: usize = 6 * 1024 * 1024;

/// Protocol message tag — identifies the type of a framed WebSocket message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tag {
    // ---- active tags (lexicographic order of wire bytes) ----
    AgreementVote,
    MsgOfInterest,
    MsgDigestSkip,
    NetIDVerification,
    NetPrioResponse,
    ProposalPayload,
    StateProofSig,
    TopicMsgResp,
    Transaction,
    UniEnsBlockReq,
    VoteBundle,
    VotePacked,

    // ---- deprecated tags ----
    /// Deprecated: removed in 3.2.1 (was Ping).
    PingDeprecated,
    /// Deprecated: removed in 3.2.1 (was PingReply).
    PingReplyDeprecated,
}

impl Tag {
    /// Returns the 2-byte ASCII wire representation of this tag.
    pub fn as_bytes(&self) -> [u8; 2] {
        match self {
            Tag::AgreementVote => *b"AV",
            Tag::MsgOfInterest => *b"MI",
            Tag::MsgDigestSkip => *b"MS",
            Tag::NetIDVerification => *b"NI",
            Tag::NetPrioResponse => *b"NP",
            Tag::ProposalPayload => *b"PP",
            Tag::StateProofSig => *b"SP",
            Tag::TopicMsgResp => *b"TS",
            Tag::Transaction => *b"TX",
            Tag::UniEnsBlockReq => *b"UE",
            Tag::VoteBundle => *b"VB",
            Tag::VotePacked => *b"VP",
            Tag::PingDeprecated => *b"pi",
            Tag::PingReplyDeprecated => *b"pj",
        }
    }

    /// Parse a 2-byte ASCII slice into a `Tag`.
    ///
    /// Returns `None` for unrecognised byte pairs.
    pub fn from_bytes(bytes: &[u8]) -> Option<Tag> {
        if bytes.len() < TAG_LENGTH {
            return None;
        }
        match [bytes[0], bytes[1]] {
            b if b == *b"AV" => Some(Tag::AgreementVote),
            b if b == *b"MI" => Some(Tag::MsgOfInterest),
            b if b == *b"MS" => Some(Tag::MsgDigestSkip),
            b if b == *b"NI" => Some(Tag::NetIDVerification),
            b if b == *b"NP" => Some(Tag::NetPrioResponse),
            b if b == *b"PP" => Some(Tag::ProposalPayload),
            b if b == *b"SP" => Some(Tag::StateProofSig),
            b if b == *b"TS" => Some(Tag::TopicMsgResp),
            b if b == *b"TX" => Some(Tag::Transaction),
            b if b == *b"UE" => Some(Tag::UniEnsBlockReq),
            b if b == *b"VB" => Some(Tag::VoteBundle),
            b if b == *b"VP" => Some(Tag::VotePacked),
            b if b == *b"pi" => Some(Tag::PingDeprecated),
            b if b == *b"pj" => Some(Tag::PingReplyDeprecated),
            _ => None,
        }
    }

    /// Maximum payload size for this tag in bytes.
    ///
    /// Values are taken verbatim from `go-algorand/protocol/tags.go`.
    /// Deprecated tags return 0 (no messages should be received for them).
    pub fn max_message_size(&self) -> usize {
        match self {
            Tag::AgreementVote => 1_228,
            Tag::MsgOfInterest => 48,
            Tag::MsgDigestSkip => 69,
            Tag::NetPrioResponse => 850,
            Tag::NetIDVerification => 215,
            Tag::ProposalPayload => 5_250_594,
            Tag::StateProofSig => 6_378,
            Tag::TopicMsgResp => 6 * 1024 * 1024, // == MAX_MESSAGE_LENGTH
            Tag::Transaction => 5_000_000,
            Tag::UniEnsBlockReq => 67,
            Tag::VoteBundle => 6 * 1024 * 1024, // == MAX_MESSAGE_LENGTH
            Tag::VotePacked => 1_228,           // same as AgreementVote
            Tag::PingDeprecated | Tag::PingReplyDeprecated => 0,
        }
    }

    /// Returns the 2-character ASCII code as a `&str`.
    ///
    /// This is the string form used in MsgOfInterest comma-separated lists.
    pub fn as_str(&self) -> &'static str {
        match self {
            Tag::AgreementVote => "AV",
            Tag::MsgOfInterest => "MI",
            Tag::MsgDigestSkip => "MS",
            Tag::NetIDVerification => "NI",
            Tag::NetPrioResponse => "NP",
            Tag::ProposalPayload => "PP",
            Tag::StateProofSig => "SP",
            Tag::TopicMsgResp => "TS",
            Tag::Transaction => "TX",
            Tag::UniEnsBlockReq => "UE",
            Tag::VoteBundle => "VB",
            Tag::VotePacked => "VP",
            Tag::PingDeprecated => "pi",
            Tag::PingReplyDeprecated => "pj",
        }
    }

    /// Parse a 2-character string code into a `Tag`.
    ///
    /// Returns `None` for unrecognised codes.
    pub fn from_code(s: &str) -> Option<Tag> {
        if s.len() != 2 {
            return None;
        }
        Tag::from_bytes(s.as_bytes())
    }

    /// Returns `true` if the given 2-character code is a deprecated tag.
    pub fn is_deprecated_code(s: &str) -> bool {
        s == "pi" || s == "pj"
    }

    /// Returns a `Vec` of all active (non-deprecated) tags.
    pub fn active_tags() -> Vec<Tag> {
        Tag::ACTIVE_TAGS.to_vec()
    }

    /// Returns `true` if this is an active (non-deprecated) tag.
    pub fn is_active(&self) -> bool {
        !matches!(self, Tag::PingDeprecated | Tag::PingReplyDeprecated)
    }

    /// All active tags, in the same order as Go's `TagList`.
    pub const ACTIVE_TAGS: [Tag; 12] = [
        Tag::AgreementVote,
        Tag::MsgOfInterest,
        Tag::MsgDigestSkip,
        Tag::NetIDVerification,
        Tag::NetPrioResponse,
        Tag::ProposalPayload,
        Tag::StateProofSig,
        Tag::TopicMsgResp,
        Tag::Transaction,
        Tag::UniEnsBlockReq,
        Tag::VoteBundle,
        Tag::VotePacked,
    ];

    /// Deprecated tags that may still appear in MsgOfInterest messages.
    pub const DEPRECATED_TAGS: [Tag; 2] = [Tag::PingDeprecated, Tag::PingReplyDeprecated];
}

impl std::fmt::Display for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<[u8; 2]> for Tag {
    type Error = [u8; 2];

    fn try_from(value: [u8; 2]) -> Result<Self, Self::Error> {
        Tag::from_bytes(&value).ok_or(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_tags() {
        let all: Vec<Tag> = Tag::ACTIVE_TAGS
            .iter()
            .chain(Tag::DEPRECATED_TAGS.iter())
            .copied()
            .collect();
        for tag in &all {
            let bytes = tag.as_bytes();
            let parsed = Tag::from_bytes(&bytes).expect("should parse known tag");
            assert_eq!(*tag, parsed);
        }
    }

    #[test]
    fn try_from_array() {
        assert_eq!(Tag::try_from(*b"AV"), Ok(Tag::AgreementVote));
        assert_eq!(Tag::try_from(*b"TX"), Ok(Tag::Transaction));
        assert!(Tag::try_from(*b"ZZ").is_err());
    }

    #[test]
    fn from_bytes_too_short() {
        assert_eq!(Tag::from_bytes(b"A"), None);
        assert_eq!(Tag::from_bytes(b""), None);
    }

    #[test]
    fn from_bytes_unknown() {
        assert_eq!(Tag::from_bytes(b"ZZ"), None);
        assert_eq!(Tag::from_bytes(b"\x00\x00"), None);
    }

    #[test]
    fn max_sizes_match_go() {
        // Spot-check values from go-algorand/protocol/tags.go
        assert_eq!(Tag::AgreementVote.max_message_size(), 1_228);
        assert_eq!(Tag::MsgOfInterest.max_message_size(), 48);
        assert_eq!(Tag::MsgDigestSkip.max_message_size(), 69);
        assert_eq!(Tag::NetPrioResponse.max_message_size(), 850);
        assert_eq!(Tag::NetIDVerification.max_message_size(), 215);
        assert_eq!(Tag::ProposalPayload.max_message_size(), 5_250_594);
        assert_eq!(Tag::StateProofSig.max_message_size(), 6_378);
        assert_eq!(Tag::TopicMsgResp.max_message_size(), 6 * 1024 * 1024);
        assert_eq!(Tag::Transaction.max_message_size(), 5_000_000);
        assert_eq!(Tag::UniEnsBlockReq.max_message_size(), 67);
        assert_eq!(Tag::VoteBundle.max_message_size(), 6 * 1024 * 1024);
        assert_eq!(Tag::VotePacked.max_message_size(), 1_228);
    }

    #[test]
    fn deprecated_tags_have_zero_max_size() {
        assert_eq!(Tag::PingDeprecated.max_message_size(), 0);
        assert_eq!(Tag::PingReplyDeprecated.max_message_size(), 0);
    }

    #[test]
    fn tag_display() {
        assert_eq!(Tag::AgreementVote.to_string(), "AV");
        assert_eq!(Tag::Transaction.to_string(), "TX");
        assert_eq!(Tag::PingDeprecated.to_string(), "pi");
    }

    #[test]
    fn is_active() {
        assert!(Tag::AgreementVote.is_active());
        assert!(Tag::Transaction.is_active());
        assert!(!Tag::PingDeprecated.is_active());
        assert!(!Tag::PingReplyDeprecated.is_active());
    }

    #[test]
    fn tag_length_constant() {
        assert_eq!(TAG_LENGTH, 2);
        for tag in &Tag::ACTIVE_TAGS {
            assert_eq!(tag.as_bytes().len(), TAG_LENGTH);
        }
    }

    #[test]
    fn max_message_length_constant() {
        assert_eq!(MAX_MESSAGE_LENGTH, 6 * 1024 * 1024);
    }
}
