//! Network message containers.
//!
//! These are simple data types that carry a tag + payload through the
//! networking stack.  They correspond to `IncomingMessage` and
//! `OutgoingMessage` in `go-algorand/network/gossipNode.go`.

use crate::tag::Tag;

/// A message received from a remote peer.
///
/// Mirrors Go's `network.IncomingMessage`.  For now this is a minimal data
/// container; fields like `Net` and `processing` are omitted until the
/// higher-level peer management layer is built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingMessage {
    /// The protocol tag identifying the message type.
    pub tag: Tag,

    /// The raw payload bytes (after the 2-byte tag has been stripped).
    pub data: Vec<u8>,

    /// Address of the peer that sent this message (e.g. "1.2.3.4:4160").
    pub sender: String,

    /// Timestamp when the message was received, as nanoseconds since the
    /// Unix epoch (matches Go's `time.Time.UnixNano()`).
    pub received_at: i64,
}

impl IncomingMessage {
    /// Create a new `IncomingMessage`.
    pub fn new(tag: Tag, data: Vec<u8>, sender: String, received_at: i64) -> Self {
        Self {
            tag,
            data,
            sender,
            received_at,
        }
    }
}

/// A message to be sent to one or more peers.
///
/// Mirrors Go's `network.OutgoingMessage` (simplified — forwarding policy
/// and topic fields are deferred to the routing layer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingMessage {
    /// The protocol tag identifying the message type.
    pub tag: Tag,

    /// The raw payload bytes (the 2-byte tag is prepended during framing).
    pub payload: Vec<u8>,
}

impl OutgoingMessage {
    /// Create a new `OutgoingMessage`.
    pub fn new(tag: Tag, payload: Vec<u8>) -> Self {
        Self { tag, payload }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incoming_message_construction() {
        let msg = IncomingMessage::new(
            Tag::Transaction,
            vec![1, 2, 3],
            "127.0.0.1:4160".to_string(),
            1_700_000_000_000_000_000,
        );
        assert_eq!(msg.tag, Tag::Transaction);
        assert_eq!(msg.data, vec![1, 2, 3]);
        assert_eq!(msg.sender, "127.0.0.1:4160");
        assert_eq!(msg.received_at, 1_700_000_000_000_000_000);
    }

    #[test]
    fn outgoing_message_construction() {
        let msg = OutgoingMessage::new(Tag::AgreementVote, vec![0xAB, 0xCD]);
        assert_eq!(msg.tag, Tag::AgreementVote);
        assert_eq!(msg.payload, vec![0xAB, 0xCD]);
    }

    #[test]
    fn incoming_message_clone_eq() {
        let msg = IncomingMessage::new(Tag::MsgOfInterest, vec![], "10.0.0.1:4161".to_string(), 42);
        let cloned = msg.clone();
        assert_eq!(msg, cloned);
    }

    #[test]
    fn outgoing_message_empty_payload() {
        let msg = OutgoingMessage::new(Tag::MsgOfInterest, vec![]);
        assert!(msg.payload.is_empty());
    }
}
