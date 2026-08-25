//! Placeholder for libp2p request/response stream handling.
//!
//! Go's `network/p2p/streams.go` and `network/p2p/http.go` implement a
//! stream manager that multiplexes Algorand's WS-gossip protocol (and an
//! HTTP-over-libp2p-streams client) on top of the host built in [`crate::host`].
//! Neither is needed to satisfy this issue's acceptance criteria (dial/listen
//! foundation only, no protocol traffic yet), so this module is intentionally
//! left as a stub: it exists so later sub-issues (gossipsub wiring in #540,
//! capability/HTTP-over-stream needs in #541) have an obvious place to land
//! stream-protocol handlers without having to first invent the module.
//!
//! [`StreamProtocol`] is re-exported here (rather than requiring downstream
//! callers to reach into `libp2p` directly) since it is the type later
//! sub-issues will register handlers against.

pub use libp2p::StreamProtocol;
