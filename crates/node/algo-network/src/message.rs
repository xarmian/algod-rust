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

//! Network message containers.
//!
//! These are simple data types that carry a tag + payload through the
//! networking stack.  They correspond to `IncomingMessage` and
//! `OutgoingMessage` in `go-algorand/network/gossipNode.go`.

use std::sync::Arc;

use crate::forwarding_policy::ForwardingPolicy;
use crate::tag::Tag;
use crate::topics::Topics;
use crate::ws_peer::PeerSender;

/// A message received from a remote peer.
///
/// Mirrors Go's `network.IncomingMessage`.  The `peer` field provides a
/// shareable reference to the sending peer so that message handlers can
/// respond (unicast) or disconnect the sender.
#[derive(Clone)]
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

    /// Shareable reference to the peer that sent this message.
    ///
    /// Wrapped in `Arc` so it can be shared across handlers and tasks.
    /// `None` when the message was constructed synthetically (e.g. in tests).
    pub peer: Option<Arc<PeerSender>>,
}

impl PartialEq for IncomingMessage {
    fn eq(&self, other: &Self) -> bool {
        // Compare value fields only — the peer handle is an opaque resource
        // that doesn't have meaningful equality semantics.
        self.tag == other.tag
            && self.data == other.data
            && self.sender == other.sender
            && self.received_at == other.received_at
    }
}

impl Eq for IncomingMessage {}

impl std::fmt::Debug for IncomingMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncomingMessage")
            .field("tag", &self.tag)
            .field("data_len", &self.data.len())
            .field("sender", &self.sender)
            .field("received_at", &self.received_at)
            .field("peer", &self.peer.as_ref().map(|p| p.remote_addr()))
            .finish()
    }
}

impl IncomingMessage {
    /// Create a new `IncomingMessage` without a peer handle.
    ///
    /// This is the original constructor kept for backward compatibility and
    /// for test code that doesn't need peer access.
    pub fn new(tag: Tag, data: Vec<u8>, sender: String, received_at: i64) -> Self {
        Self {
            tag,
            data,
            sender,
            received_at,
            peer: None,
        }
    }

    /// Create a new `IncomingMessage` with a peer sender reference.
    pub fn with_peer(
        tag: Tag,
        data: Vec<u8>,
        sender: String,
        received_at: i64,
        peer: Arc<PeerSender>,
    ) -> Self {
        Self {
            tag,
            data,
            sender,
            received_at,
            peer: Some(peer),
        }
    }
}

/// A message to be sent to one or more peers.
///
/// Mirrors Go's `network.OutgoingMessage`.  The `action` field tells the
/// network layer what to do with the message (broadcast, respond, ignore,
/// etc.) and `topics` carries optional key-value metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingMessage {
    /// The forwarding action the network layer should take.
    pub action: ForwardingPolicy,

    /// The protocol tag identifying the message type.
    pub tag: Tag,

    /// The raw payload bytes (the 2-byte tag is prepended during framing).
    pub payload: Vec<u8>,

    /// Optional key-value topic data attached to the message.
    ///
    /// Corresponds to Go's `OutgoingMessage.Topics`.
    pub topics: Option<Topics>,
}

impl OutgoingMessage {
    /// Create a new `OutgoingMessage` with `action: Ignore` (the default).
    ///
    /// This preserves the original two-argument API for backward
    /// compatibility.  Callers that need a different action should use
    /// [`OutgoingMessage::propagate`] or set the `action` field directly.
    pub fn new(tag: Tag, payload: Vec<u8>) -> Self {
        Self {
            action: ForwardingPolicy::default(),
            tag,
            payload,
            topics: None,
        }
    }

    /// Create an `OutgoingMessage` with `action: Broadcast`.
    ///
    /// Convenience constructor for the common case where a handler wants to
    /// propagate a message to all peers (except the sender).
    pub fn propagate(tag: Tag, payload: Vec<u8>) -> Self {
        Self {
            action: ForwardingPolicy::Broadcast,
            tag,
            payload,
            topics: None,
        }
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
        assert!(msg.peer.is_none());
    }

    #[test]
    fn outgoing_message_construction() {
        let msg = OutgoingMessage::new(Tag::AgreementVote, vec![0xAB, 0xCD]);
        assert_eq!(msg.tag, Tag::AgreementVote);
        assert_eq!(msg.payload, vec![0xAB, 0xCD]);
        assert_eq!(msg.action, ForwardingPolicy::Ignore);
        assert!(msg.topics.is_none());
    }

    #[test]
    fn outgoing_message_propagate() {
        let msg = OutgoingMessage::propagate(Tag::Transaction, vec![1, 2, 3]);
        assert_eq!(msg.action, ForwardingPolicy::Broadcast);
        assert_eq!(msg.tag, Tag::Transaction);
        assert_eq!(msg.payload, vec![1, 2, 3]);
        assert!(msg.topics.is_none());
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

    #[test]
    fn outgoing_message_with_topics() {
        let topics = Topics(vec![]);
        let msg = OutgoingMessage {
            action: ForwardingPolicy::Respond,
            tag: Tag::TopicMsgResp,
            payload: vec![],
            topics: Some(topics),
        };
        assert_eq!(msg.action, ForwardingPolicy::Respond);
        assert!(msg.topics.is_some());
    }

    #[test]
    fn forwarding_policy_default_on_outgoing() {
        let msg = OutgoingMessage::new(Tag::Transaction, vec![]);
        assert_eq!(msg.action, ForwardingPolicy::Ignore);
    }
}
