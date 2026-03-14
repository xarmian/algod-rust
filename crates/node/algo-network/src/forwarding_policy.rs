//! Forwarding policy for network message handling.
//!
//! Determines what action the network layer should take after a message
//! handler processes an incoming message.
//!
//! Reference: `go-algorand/network/gossipNode.go` — `ForwardingPolicy` type
//! and its constants (`Ignore`, `Disconnect`, `Broadcast`, `Respond`, `Accept`).

/// Indicates to whom (if anyone) we should forward a message after a
/// handler processes it.
///
/// Mirrors Go's `network.ForwardingPolicy` enum (iota-based).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForwardingPolicy {
    /// Discard the message — do not forward.
    Ignore,

    /// Disconnect from the peer that sent this message.
    Disconnect,

    /// Forward the message to all peers except the sender.
    Broadcast,

    /// Reply directly to the sender (unicast).
    Respond,

    /// Accept the message for further processing after successful validation.
    Accept,
}

impl Default for ForwardingPolicy {
    /// Default is `Ignore`, matching Go's zero-value semantics where the
    /// `ForwardingPolicy` int type defaults to 0 which is `Ignore`.
    fn default() -> Self {
        Self::Ignore
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_ignore() {
        assert_eq!(ForwardingPolicy::default(), ForwardingPolicy::Ignore);
    }

    #[test]
    fn variants_are_distinct() {
        let variants = [
            ForwardingPolicy::Ignore,
            ForwardingPolicy::Disconnect,
            ForwardingPolicy::Broadcast,
            ForwardingPolicy::Respond,
            ForwardingPolicy::Accept,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn clone_and_copy() {
        let p = ForwardingPolicy::Broadcast;
        let copied = p;
        assert_eq!(p, copied);
        // Clone trait is derived (via Copy) but clippy warns about .clone()
        // on Copy types, so just verify equality after copy.
    }

    #[test]
    fn debug_format() {
        let s = format!("{:?}", ForwardingPolicy::Respond);
        assert!(s.contains("Respond"));
    }
}
