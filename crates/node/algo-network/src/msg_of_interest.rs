//! Message-of-Interest (MI) encoding and decoding.
//!
//! When a peer connects, it sends a MI message describing which protocol tags
//! it is interested in receiving. The payload is a [`Topics`] collection with
//! a single topic whose key is `"tags"` and whose value is a comma-separated
//! list of two-character tag codes (e.g. `"AV,PP,TX"`).
//!
//! Reference: go-algorand/network/msgOfInterest.go

use std::collections::HashSet;

use crate::tag::Tag;
use crate::topics::{Topic, Topics, TopicsError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Key used inside the Topics payload of an MI message.
const TAGS_KEY: &str = "tags";

/// Separator between tag codes in the comma-separated value.
const SEPARATOR: &str = ",";

/// Maximum byte length of the tags value string.
const MAX_MSG_OF_INTEREST_TAGS: usize = 1024;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors arising from MI message encoding / decoding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MsgOfInterestError {
    #[error("could not unmarshal message: {0}")]
    UnmarshalFailed(TopicsError),

    #[error("message missing the tags key")]
    MissingTagsKey,

    #[error("tags value length {0} exceeds maximum of {MAX_MSG_OF_INTEREST_TAGS}")]
    TagsTooLong(usize),

    #[error("invalid tag: {0:?}")]
    InvalidTag(String),
}

impl From<TopicsError> for MsgOfInterestError {
    fn from(e: TopicsError) -> Self {
        MsgOfInterestError::UnmarshalFailed(e)
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Serialize a list of tags into an MI message payload (Topics binary format).
///
/// Produces a Topics with one entry: key=`"tags"`, value = comma-separated tag
/// codes (e.g. `"AV,PP,TX"`).
pub fn marshal_msg_of_interest(tags: &[Tag]) -> Vec<u8> {
    // Deduplicate via a set (matches Go which uses map[Tag]bool)
    let mut seen = HashSet::with_capacity(tags.len());
    let mut parts: Vec<&str> = Vec::with_capacity(tags.len());
    for tag in tags {
        if seen.insert(tag) {
            parts.push(tag.as_str());
        }
    }
    let value = parts.join(SEPARATOR);
    let topics = Topics::from_vec(vec![Topic::new(TAGS_KEY, value.into_bytes())]);
    topics.marshal()
}

/// Deserialize an MI message payload into a set of [`Tag`] values.
///
/// Deprecated tags (`pi`, `pj`) are silently skipped. Unknown or malformed
/// tags produce an error.
pub fn unmarshal_msg_of_interest(data: &[u8]) -> Result<HashSet<Tag>, MsgOfInterestError> {
    let topics = Topics::unmarshal(data)?;

    let tags_bytes = topics
        .get_value(TAGS_KEY)
        .ok_or(MsgOfInterestError::MissingTagsKey)?;

    if tags_bytes.len() > MAX_MSG_OF_INTEREST_TAGS {
        return Err(MsgOfInterestError::TagsTooLong(tags_bytes.len()));
    }

    let tags_str = std::str::from_utf8(tags_bytes)
        .map_err(|_| MsgOfInterestError::InvalidTag("<non-utf8>".to_string()))?;

    let mut result = HashSet::new();

    if tags_str.is_empty() {
        return Ok(result);
    }

    for part in tags_str.split(SEPARATOR) {
        // Go requires TagLength == 2
        if part.len() != 2 {
            return Err(MsgOfInterestError::InvalidTag(part.to_string()));
        }

        // Silently skip deprecated tags
        if Tag::is_deprecated_code(part) {
            continue;
        }

        let tag =
            Tag::from_code(part).ok_or_else(|| MsgOfInterestError::InvalidTag(part.to_string()))?;
        result.insert(tag);
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_single_tag() {
        let tags = vec![Tag::Transaction];
        let bytes = marshal_msg_of_interest(&tags);
        let decoded = unmarshal_msg_of_interest(&bytes).unwrap();
        assert_eq!(decoded.len(), 1);
        assert!(decoded.contains(&Tag::Transaction));
    }

    #[test]
    fn round_trip_multiple_tags() {
        let tags = vec![Tag::AgreementVote, Tag::ProposalPayload, Tag::Transaction];
        let bytes = marshal_msg_of_interest(&tags);
        let decoded = unmarshal_msg_of_interest(&bytes).unwrap();
        assert_eq!(decoded.len(), 3);
        assert!(decoded.contains(&Tag::AgreementVote));
        assert!(decoded.contains(&Tag::ProposalPayload));
        assert!(decoded.contains(&Tag::Transaction));
    }

    #[test]
    fn round_trip_empty_tags() {
        let tags: Vec<Tag> = vec![];
        let bytes = marshal_msg_of_interest(&tags);
        let decoded = unmarshal_msg_of_interest(&bytes).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn deprecated_tags_skipped() {
        // Manually build a Topics payload with deprecated tag "pi"
        let value = "AV,pi,TX";
        let topics = Topics::from_vec(vec![Topic::new(TAGS_KEY, value.as_bytes().to_vec())]);
        let bytes = topics.marshal();
        let decoded = unmarshal_msg_of_interest(&bytes).unwrap();
        // "pi" should be silently dropped
        assert_eq!(decoded.len(), 2);
        assert!(decoded.contains(&Tag::AgreementVote));
        assert!(decoded.contains(&Tag::Transaction));
        assert!(!decoded.iter().any(|t| t.as_str() == "pi"));
    }

    #[test]
    fn deprecated_pj_skipped() {
        let value = "pj,PP";
        let topics = Topics::from_vec(vec![Topic::new(TAGS_KEY, value.as_bytes().to_vec())]);
        let bytes = topics.marshal();
        let decoded = unmarshal_msg_of_interest(&bytes).unwrap();
        assert_eq!(decoded.len(), 1);
        assert!(decoded.contains(&Tag::ProposalPayload));
    }

    #[test]
    fn unknown_tag_error() {
        let value = "AV,ZZ";
        let topics = Topics::from_vec(vec![Topic::new(TAGS_KEY, value.as_bytes().to_vec())]);
        let bytes = topics.marshal();
        let err = unmarshal_msg_of_interest(&bytes).unwrap_err();
        assert!(matches!(err, MsgOfInterestError::InvalidTag(ref s) if s == "ZZ"));
    }

    #[test]
    fn invalid_tag_length_error() {
        let value = "AV,TOOLONG";
        let topics = Topics::from_vec(vec![Topic::new(TAGS_KEY, value.as_bytes().to_vec())]);
        let bytes = topics.marshal();
        let err = unmarshal_msg_of_interest(&bytes).unwrap_err();
        assert!(matches!(err, MsgOfInterestError::InvalidTag(_)));
    }

    #[test]
    fn missing_tags_key_error() {
        let topics = Topics::from_vec(vec![Topic::new("other", b"data".to_vec())]);
        let bytes = topics.marshal();
        let err = unmarshal_msg_of_interest(&bytes).unwrap_err();
        assert!(matches!(err, MsgOfInterestError::MissingTagsKey));
    }

    #[test]
    fn tags_too_long_error() {
        // Create a value longer than 1024 bytes
        let long_value = "AV,".repeat(500); // 3 * 500 = 1500 bytes
        let topics = Topics::from_vec(vec![Topic::new(TAGS_KEY, long_value.into_bytes())]);
        let bytes = topics.marshal();
        let err = unmarshal_msg_of_interest(&bytes).unwrap_err();
        assert!(matches!(err, MsgOfInterestError::TagsTooLong(_)));
    }

    #[test]
    fn corrupt_topics_data_error() {
        let err = unmarshal_msg_of_interest(&[0xFF, 0xFF, 0xFF]).unwrap_err();
        assert!(matches!(err, MsgOfInterestError::UnmarshalFailed(_)));
    }

    #[test]
    fn duplicate_tags_deduplicated_on_marshal() {
        let tags = vec![Tag::Transaction, Tag::Transaction, Tag::AgreementVote];
        let bytes = marshal_msg_of_interest(&tags);
        let decoded = unmarshal_msg_of_interest(&bytes).unwrap();
        assert_eq!(decoded.len(), 2);
    }

    #[test]
    fn all_active_tags_round_trip() {
        let all_tags = Tag::active_tags();
        let bytes = marshal_msg_of_interest(&all_tags);
        let decoded = unmarshal_msg_of_interest(&bytes).unwrap();
        assert_eq!(decoded.len(), all_tags.len());
        for tag in &all_tags {
            assert!(decoded.contains(tag), "missing tag: {:?}", tag);
        }
    }
}
