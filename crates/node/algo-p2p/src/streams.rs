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

//! Stream lifecycle bookkeeping mirroring go-algorand's libp2p
//! `streamManager` (`../go-algorand/network/p2p/streams.go`).
//!
//! # Why this is a standalone state-tracking module, not a live `Notifiee`
//!
//! Go's `streamManager` implements `network.Notifiee` and is wired directly
//! into a `libp2p-go` `Swarm`'s connection-event stream: `Connected`/
//! `Disconnected` fire from inside `Swarm.notifyAll`, and `streamHandler`
//! is registered as the libp2p stream handler for each protocol the node
//! speaks. `rust-libp2p` (this crate's transport, via
//! [`crate::host::P2pHost`]) has no equivalent `Notifiee` trait — connection
//! and stream lifecycle surface instead as [`libp2p::swarm::SwarmEvent`]s
//! from [`crate::host::P2pHost::next_event`], and per-protocol stream
//! accept/open is `libp2p-stream`'s [`libp2p_stream::Control`] (already
//! exposed via [`crate::host::P2pHost::stream_control`]).
//!
//! Rather than force-fitting a `Notifiee` shape that doesn't exist in this
//! stack, this module ports the *decision logic* go's `streamManager`
//! encodes — the part that is genuinely protocol/algorithm, not go-libp2p
//! API surface — as a transport-agnostic, directly-testable state machine:
//!
//! - **In-flight attempt counting** (`beginPeerAttempt`/`endPeerAttempt`):
//!   tracks how many concurrent stream-open/accept attempts are running for
//!   a peer, and reports (via a `bool` return, mirroring go's
//!   `shouldUnprotect` local) whether the connection-manager "protect this
//!   peer" tag should now be released — only once neither a live stream nor
//!   any in-flight attempt remains for that peer, and (per
//!   `TestStream_ConcurrentBadAttemptsUnprotectOnce`) exactly once even if
//!   several concurrent attempts fail together.
//! - **The stream map's replace/keep-old semantics**
//!   (`streamHandler`/`handleConnected`/`Disconnected`): a *successfully*
//!   dispatched stream replaces whatever was there before (the caller closes
//!   the displaced one, `TestStream_HandlerDispatchesBeforeTouchingOldStream`);
//!   a stream that fails dispatch is never installed, so a healthy existing
//!   stream survives a concurrent bad attempt untouched
//!   (`TestStream_HandlerKeepsOldStreamOnDispatchProblem`).
//! - **Protocol dispatch** (`dispatch`): first-match lookup by negotiated
//!   [`StreamProtocol`] against a handler table, erroring
//!   `"no handler for protocol"` like go's `dispatch` when nothing matches.
//! - **The single-initiator ordering rule** (`Connected`'s
//!   `localPeer > remotePeer` check): of the two peers on a connection,
//!   only the numerically lower `PeerId` opens the outbound stream; the
//!   higher one waits to receive it via its inbound stream handler. This
//!   is pure `PeerId` comparison, verifiable without any live connection.
//! - **Dispatch-error log-level selection** (`logDispatchError`): a
//!   [`StreamHandlerLoggedError`]-shaped error carries its own intended
//!   severity; a bare error defaults to `Error`, mirroring go's
//!   `TestLogDispatchErrorDebugLevel`/`TestLogDispatchErrorErrorLevel`.
//!
//! A caller wiring this into a live `P2pHost` event loop (a later
//! integration step, deliberately out of scope for this issue per its
//! safe-scoping note — see this crate's `README`/issue #818) would drive
//! [`StreamManager::begin_peer_attempt`]/[`end_peer_attempt`] and
//! [`StreamManager::set_stream`]/[`remove_stream`] from
//! [`libp2p::swarm::SwarmEvent::ConnectionEstablished`]/`ConnectionClosed`
//! and from [`libp2p_stream::Control::accept`]/`open_stream` outcomes,
//! exactly as go's `streamManager` drives them from its own `Connected`/
//! `Disconnected`/`streamHandler` callbacks — but no such wiring exists yet
//! in [`crate::host`], so this module changes no currently-observable P2P
//! transport behavior.
//!
//! [`StreamProtocol`] is re-exported here (rather than requiring downstream
//! callers to reach into `libp2p` directly) since it is the type handler
//! registration is keyed on.
//!
//! Reference: `../go-algorand/network/p2p/streams.go` (`streamManager`,
//! `beginPeerAttempt`/`endPeerAttempt`, `streamHandler`, `handleConnected`,
//! `Disconnected`, `Connected`, `dispatch`, `logDispatchError`),
//! `network/p2p/streams_test.go`, `network/p2p/streams_stale_test.go`.

use std::collections::HashMap;
use std::fmt;

use libp2p::PeerId;

pub use libp2p::StreamProtocol;

/// The log severity a dispatch error should be reported at, mirroring go's
/// `logging.Level` values `StreamHandlerLoggedError` can carry
/// (`Debug`/`Info`/`Warn`/`Error` — go's `logDispatchError` switches on
/// exactly these four).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// An error produced while dispatching a stream to its protocol handler.
///
/// Go: `StreamHandlerLoggedError` — an error with an associated log level,
/// so a handler can signal severity without the stream manager needing to
/// inspect the error's cause. A `level` of `None` mirrors a plain
/// (non-`StreamHandlerLoggedError`) error in go, which `logDispatchError`
/// always logs at [`LogLevel::Error`].
#[derive(Debug, Clone)]
pub struct DispatchError {
    message: String,
    level: Option<LogLevel>,
}

impl DispatchError {
    /// Construct a plain dispatch error with no explicit severity — logs at
    /// [`LogLevel::Error`], matching go's default for an unwrapped error.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            level: None,
        }
    }

    /// Construct a dispatch error carrying an explicit intended severity.
    /// Go: `&StreamHandlerLoggedError{Err: err, Level: level}`.
    pub fn with_level(message: impl Into<String>, level: LogLevel) -> Self {
        Self {
            message: message.into(),
            level: Some(level),
        }
    }

    /// Go: `dispatch`'s `"%s: no handler for protocol %s, peer %s"`.
    pub fn no_handler(local: PeerId, protocol: &StreamProtocol, remote: PeerId) -> Self {
        Self::new(format!(
            "{local}: no handler for protocol {protocol}, peer {remote}"
        ))
    }

    /// The log level this error should be reported at. Go: `logDispatchError`'s
    /// `errors.As(err, &le)` check, defaulting to `Error` when the error
    /// isn't a `StreamHandlerLoggedError`.
    pub fn log_level(&self) -> LogLevel {
        self.level.unwrap_or(LogLevel::Error)
    }
}

impl fmt::Display for DispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DispatchError {}

/// A single protocol-ID-to-handler registration. Go: one element of the
/// `StreamHandlers` slice `makeStreamManager` is constructed with.
#[derive(Clone)]
pub struct HandlerEntry<H> {
    pub protocol: StreamProtocol,
    pub handler: H,
}

/// The set of protocol handlers a [`StreamManager`] dispatches against. Go:
/// `StreamHandlers` (`[]struct{ ProtoID protocol.ID; Handler StreamHandler }`).
pub type StreamHandlers<H> = Vec<HandlerEntry<H>>;

/// First-match lookup of the handler registered for `protocol`.
///
/// Go: `streamManager.dispatch`'s handler-table scan (this function returns
/// the matched handler rather than invoking it, since a real handler
/// invocation is async I/O this transport-agnostic module deliberately
/// doesn't own — see this module's doc comment).
pub fn find_handler<'a, H>(
    handlers: &'a [HandlerEntry<H>],
    protocol: &StreamProtocol,
) -> Option<&'a H> {
    handlers
        .iter()
        .find(|entry| &entry.protocol == protocol)
        .map(|entry| &entry.handler)
}

/// Go: `streamManager.Connected`'s ordering rule — `if localPeer >
/// remotePeer { ignore }`. Of the two ends of a connection, only the
/// numerically lower `PeerId` opens the outbound stream that will carry the
/// negotiated protocol; the other side waits to receive it inbound. Since
/// both peers derive this from the same pair of (cryptographically fixed)
/// `PeerId`s, they agree on who initiates without any coordination message.
pub fn should_initiate_stream(local: &PeerId, remote: &PeerId) -> bool {
    local < remote
}

/// Stream lifecycle state for one node: which peer currently has an active
/// stream, and how many stream-open/accept attempts are in flight per peer.
///
/// Generic over the stream handle type `S` so this module stays independent
/// of any specific transport's `Stream` type (a real caller would
/// instantiate this with `libp2p_stream::Stream` or similar; tests below use
/// plain mock handles).
///
/// Go: `streamManager`'s `streams`/`inflight` maps plus `streamsLock`. This
/// type does not itself provide locking — a concurrent caller (mirroring
/// go's `deadlock.Mutex`) is expected to serialize access with its own
/// `Mutex`/`RwLock`, exactly as go's callers all hold `streamsLock` around
/// these operations.
pub struct StreamManager<S> {
    streams: HashMap<PeerId, S>,
    inflight: HashMap<PeerId, u32>,
}

impl<S> Default for StreamManager<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> StreamManager<S> {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            inflight: HashMap::new(),
        }
    }

    /// Record that a stream-open/accept attempt for `remote` has started.
    /// Go: `beginPeerAttempt`.
    pub fn begin_peer_attempt(&mut self, remote: PeerId) {
        *self.inflight.entry(remote).or_insert(0) += 1;
    }

    /// Record that a stream-open/accept attempt for `remote` has finished
    /// (successfully or not). Returns `true` if the caller should now
    /// release its connection-manager "protect this peer" tag — mirroring
    /// go's `shouldUnprotect` local: true only once neither a live stream
    /// nor any other in-flight attempt remains for `remote`.
    ///
    /// Calling this exactly once per matching [`begin_peer_attempt`] call
    /// (as every go call site does, via `defer n.endPeerAttempt(...)`)
    /// guarantees the count never goes negative and multiple concurrent
    /// failed attempts unprotect at most once
    /// (`TestStream_ConcurrentBadAttemptsUnprotectOnce`).
    ///
    /// [`begin_peer_attempt`]: StreamManager::begin_peer_attempt
    pub fn end_peer_attempt(&mut self, remote: PeerId) -> bool {
        match self.inflight.get_mut(&remote) {
            Some(count) if *count > 1 => *count -= 1,
            Some(_) => {
                self.inflight.remove(&remote);
            }
            None => {}
        }
        !self.streams.contains_key(&remote) && !self.inflight.contains_key(&remote)
    }

    /// Whether a live stream is currently tracked for `remote`.
    pub fn has_stream(&self, remote: &PeerId) -> bool {
        self.streams.contains_key(remote)
    }

    /// Install a newly (successfully) dispatched stream for `remote`,
    /// returning whatever stream was previously installed, if any, so the
    /// caller can close it *after* releasing its own lock — go's
    /// `streamHandler` explicitly does the same ("Never do blocking I/O …
    /// while holding streamsLock … Dispatch the new stream first (outside
    /// the lock), then swap the map entry only on success").
    ///
    /// Must only be called after a stream has already dispatched
    /// successfully — a failed dispatch must never reach this method, which
    /// is what keeps a healthy existing stream in place when a *concurrent*
    /// attempt for the same peer fails
    /// (`TestStream_HandlerKeepsOldStreamOnDispatchProblem`).
    pub fn set_stream(&mut self, remote: PeerId, stream: S) -> Option<S> {
        self.streams.insert(remote, stream)
    }

    /// Go: `handleConnected`'s pre-flight guard — `_, ok :=
    /// n.streams[remotePeer]; if ok { return }` — true if a live stream
    /// already exists for `remote`, meaning the caller should not attempt
    /// to open (and dispatch) another one.
    pub fn should_skip_dial(&self, remote: &PeerId) -> bool {
        self.streams.contains_key(remote)
    }

    /// Remove and return the tracked stream for `remote`, if any, so the
    /// caller can close it. Go: `Disconnected`.
    pub fn remove_stream(&mut self, remote: &PeerId) -> Option<S> {
        self.streams.remove(remote)
    }

    /// The stream currently tracked for `remote`, if any. A read-only
    /// counterpart to [`StreamManager::set_stream`]/[`StreamManager::remove_stream`]
    /// for a caller that needs to inspect (not mutate) the current entry —
    /// e.g. to confirm a background task's own handle is still the one
    /// installed before that task removes it on cleanup (see
    /// `bin/algod-rust`'s `p2p_transport` module, which uses this to avoid a
    /// stale, already-replaced task's cleanup evicting a newer stream).
    pub fn get(&self, remote: &PeerId) -> Option<&S> {
        self.streams.get(remote)
    }

    /// Iterate over every peer currently tracked with a live stream, and its
    /// handle. Go has no direct equivalent (`streamManager.streams` is a
    /// private field only ever range-d over internally); exposed here since
    /// a live caller (e.g. a broadcast fan-out, or a unicast-peer listing)
    /// needs to enumerate every currently-established stream, not just query
    /// one peer at a time.
    pub fn iter(&self) -> impl Iterator<Item = (&PeerId, &S)> {
        self.streams.iter()
    }

    /// Number of peers currently tracked with a live stream.
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// True if no peer currently has a live stream tracked.
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(byte: u8) -> PeerId {
        // Deterministic PeerIds derived from a fixed Ed25519 seed byte, so
        // relative ordering between two calls is stable across test runs
        // without depending on `PeerId::random()`'s actual ordering.
        let mut seed = [0u8; 32];
        seed[0] = byte;
        let keypair = libp2p::identity::Keypair::ed25519_from_bytes(seed).expect("valid seed");
        keypair.public().to_peer_id()
    }

    // -----------------------------------------------------------------
    // find_handler / dispatch-by-protocol
    // -----------------------------------------------------------------

    #[test]
    fn find_handler_matches_registered_protocol() {
        let handlers: StreamHandlers<&str> = vec![
            HandlerEntry {
                protocol: StreamProtocol::new("/algorand-ws/1.0.0"),
                handler: "v1",
            },
            HandlerEntry {
                protocol: StreamProtocol::new("/algorand-ws/2.2.0"),
                handler: "v22",
            },
        ];
        let found = find_handler(&handlers, &StreamProtocol::new("/algorand-ws/2.2.0"));
        assert_eq!(found, Some(&"v22"));
    }

    #[test]
    fn find_handler_returns_none_for_unregistered_protocol() {
        let handlers: StreamHandlers<&str> = vec![HandlerEntry {
            protocol: StreamProtocol::new("/algorand-ws/1.0.0"),
            handler: "v1",
        }];
        assert!(find_handler(&handlers, &StreamProtocol::new("/other/1.0.0")).is_none());
    }

    #[test]
    fn no_handler_error_matches_go_message_shape() {
        let local = peer(1);
        let remote = peer(2);
        let proto = StreamProtocol::new("/algorand-ws/2.2.0");
        let err = DispatchError::no_handler(local, &proto, remote);
        let msg = err.to_string();
        assert!(msg.contains("no handler for protocol"));
        assert!(msg.contains(proto.as_ref()));
        assert_eq!(err.log_level(), LogLevel::Error);
    }

    // -----------------------------------------------------------------
    // logDispatchError level selection (TestLogDispatchErrorDebugLevel /
    // TestLogDispatchErrorErrorLevel)
    // -----------------------------------------------------------------

    #[test]
    fn logged_error_reports_its_own_level() {
        let err = DispatchError::with_level("some debug error", LogLevel::Debug);
        assert_eq!(err.log_level(), LogLevel::Debug);
        assert_eq!(err.to_string(), "some debug error");
    }

    #[test]
    fn plain_error_defaults_to_error_level() {
        let err = DispatchError::new("some plain error");
        assert_eq!(err.log_level(), LogLevel::Error);
    }

    // -----------------------------------------------------------------
    // should_initiate_stream ordering rule
    // -----------------------------------------------------------------

    #[test]
    fn lower_peer_id_initiates_the_stream() {
        // `PeerId` ordering is derived from the multihash of the public
        // key, not from the seed bytes used to generate it, so sort two
        // freshly generated ids rather than assume a seed-byte ordering.
        let a = peer(1);
        let b = peer(2);
        let (low, high) = if a < b { (a, b) } else { (b, a) };
        assert!(low < high);
        assert!(should_initiate_stream(&low, &high));
        assert!(!should_initiate_stream(&high, &low));
    }

    // -----------------------------------------------------------------
    // in-flight attempt counting / unprotect decision
    // -----------------------------------------------------------------

    #[test]
    fn single_attempt_unprotects_when_it_ends_with_no_stream() {
        let mut sm: StreamManager<&str> = StreamManager::new();
        let remote = peer(1);
        sm.begin_peer_attempt(remote);
        assert!(
            sm.end_peer_attempt(remote),
            "the only in-flight attempt ending with no installed stream must unprotect"
        );
    }

    #[test]
    fn ending_attempt_does_not_unprotect_while_stream_installed() {
        let mut sm: StreamManager<&str> = StreamManager::new();
        let remote = peer(1);
        sm.begin_peer_attempt(remote);
        sm.set_stream(remote, "stream");
        assert!(
            !sm.end_peer_attempt(remote),
            "must not unprotect while a live stream is tracked for this peer"
        );
    }

    /// Go: `TestStream_ConcurrentProblemDoesNotUnprotectWhileAnotherAttemptInFlight`.
    #[test]
    fn does_not_unprotect_while_another_attempt_is_in_flight() {
        let mut sm: StreamManager<&str> = StreamManager::new();
        let remote = peer(1);
        sm.begin_peer_attempt(remote); // successful attempt, still running
        sm.begin_peer_attempt(remote); // failing attempt

        // The failing attempt ends first; a second attempt is still in flight.
        assert!(
            !sm.end_peer_attempt(remote),
            "must not unprotect while a sibling attempt is still in flight"
        );

        // The successful attempt installs a stream, then ends.
        sm.set_stream(remote, "stream");
        assert!(
            !sm.end_peer_attempt(remote),
            "must not unprotect once a stream is installed"
        );
    }

    /// Go: `TestStream_ConcurrentBadAttemptsUnprotectOnce` — two concurrent
    /// failed attempts for the same peer must only report "unprotect" once,
    /// not twice.
    #[test]
    fn two_concurrent_bad_attempts_unprotect_exactly_once() {
        let mut sm: StreamManager<&str> = StreamManager::new();
        let remote = peer(1);
        sm.begin_peer_attempt(remote);
        sm.begin_peer_attempt(remote);

        let first = sm.end_peer_attempt(remote);
        let second = sm.end_peer_attempt(remote);

        assert!(
            !first,
            "first of two concurrent attempts must not unprotect alone"
        );
        assert!(second, "second (final) attempt must unprotect");
        assert!(!sm.has_stream(&remote));
    }

    // -----------------------------------------------------------------
    // stream map replace/keep-old semantics
    // -----------------------------------------------------------------

    #[test]
    fn set_stream_returns_previous_stream_for_caller_to_close() {
        let mut sm: StreamManager<&str> = StreamManager::new();
        let remote = peer(1);
        assert_eq!(sm.set_stream(remote, "first"), None);
        let old = sm.set_stream(remote, "second");
        assert_eq!(old, Some("first"));
        assert!(sm.has_stream(&remote));
    }

    /// Go: `TestStream_HandlerKeepsOldStreamOnDispatchProblem` — a failed
    /// dispatch must never call `set_stream`, so the existing entry is
    /// simply untouched (there is nothing this API needs to do differently;
    /// the guarantee is that the caller only calls `set_stream` after a
    /// successful dispatch). This test models a concurrent failed-dispatch
    /// attempt by simply *not* calling `set_stream` for it, and asserts the
    /// pre-existing healthy stream is still exactly what's tracked.
    #[test]
    fn failed_dispatch_never_touches_existing_stream_because_set_stream_is_not_called() {
        let mut sm: StreamManager<&str> = StreamManager::new();
        let remote = peer(1);
        sm.set_stream(remote, "healthy");

        // A concurrent failed dispatch attempt for the same peer never
        // reaches `set_stream` — nothing to call here, which is the point.

        assert!(sm.has_stream(&remote));
        assert_eq!(sm.streams.get(&remote), Some(&"healthy"));
    }

    #[test]
    fn should_skip_dial_true_only_when_stream_exists() {
        let mut sm: StreamManager<&str> = StreamManager::new();
        let remote = peer(1);
        assert!(!sm.should_skip_dial(&remote));
        sm.set_stream(remote, "stream");
        assert!(sm.should_skip_dial(&remote));
    }

    #[test]
    fn disconnected_removes_and_returns_stream() {
        let mut sm: StreamManager<&str> = StreamManager::new();
        let remote = peer(1);
        sm.set_stream(remote, "stream");
        assert_eq!(sm.remove_stream(&remote), Some("stream"));
        assert!(!sm.has_stream(&remote));
        assert_eq!(sm.remove_stream(&remote), None);
    }

    // -----------------------------------------------------------------
    // get / iter / len / is_empty — live-wiring accessors (#952)
    // -----------------------------------------------------------------

    #[test]
    fn get_reflects_the_currently_installed_stream() {
        let mut sm: StreamManager<&str> = StreamManager::new();
        let remote = peer(1);
        assert_eq!(sm.get(&remote), None);
        sm.set_stream(remote, "first");
        assert_eq!(sm.get(&remote), Some(&"first"));
        // A replacement must be visible via `get` too, so a caller checking
        // "is my handle still the installed one" (the stale-cleanup guard
        // `p2p_transport` relies on) observes the *new* value, not the old.
        sm.set_stream(remote, "second");
        assert_eq!(sm.get(&remote), Some(&"second"));
    }

    #[test]
    fn iter_and_len_enumerate_every_tracked_stream() {
        let mut sm: StreamManager<&str> = StreamManager::new();
        assert!(sm.is_empty());
        assert_eq!(sm.len(), 0);

        let a = peer(1);
        let b = peer(2);
        sm.set_stream(a, "stream-a");
        sm.set_stream(b, "stream-b");

        assert_eq!(sm.len(), 2);
        assert!(!sm.is_empty());
        let mut collected: Vec<(PeerId, &str)> = sm.iter().map(|(p, s)| (*p, *s)).collect();
        collected.sort_by_key(|(p, _)| *p);
        let mut expected = vec![(a, "stream-a"), (b, "stream-b")];
        expected.sort_by_key(|(p, _)| *p);
        assert_eq!(collected, expected);
    }
}
