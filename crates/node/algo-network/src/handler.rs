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

//! Message handler framework.
//!
//! Provides the [`MessageHandler`] and [`MessageValidatorHandler`] traits for
//! processing incoming network messages, plus the [`Multiplexer`] that
//! dispatches messages to the correct handler based on their [`Tag`].
//!
//! This mirrors the handler dispatch architecture in
//! `go-algorand/network/multiplexer.go` and the handler interfaces in
//! `go-algorand/network/gossipNode.go`.

use std::any::Any;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::forwarding_policy::ForwardingPolicy;
use crate::message::{IncomingMessage, OutgoingMessage};
use crate::tag::Tag;

/// Hex-encode a payload for the `algo_network::wire` trace target.
///
/// Only called when wire tracing is enabled; kept simple (allocates one
/// String) because it is a debugging path, never a hot path.
pub(crate) fn hex_dump(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// Handler traits
// ---------------------------------------------------------------------------

/// Processes an incoming message and returns an outgoing action.
///
/// Mirrors Go's `network.MessageHandler` interface.  Implementations must be
/// `Send + Sync` so they can be shared across async tasks, and `'static` so
/// they can be stored inside the [`Multiplexer`].
#[async_trait]
pub trait MessageHandler: Send + Sync + 'static {
    /// Handle a single incoming message and return the network action.
    async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage;
}

/// Opaque container for validated message state.
///
/// Handlers produce this during the `validate` phase so that the `handle`
/// phase can consume it without re-parsing.  The inner value is type-erased
/// via `Box<dyn Any + Send>`.
pub struct ValidatedMessage(pub Box<dyn Any + Send>);

/// Two-phase message handler: validate first, then handle.
///
/// Mirrors Go's `network.MessageValidatorHandler` interface.  The `validate`
/// method performs synchronous/fast validation and returns a
/// [`ValidatedMessage`].  If validation succeeds, the `handle` method is
/// called with the original message and the validated state.
#[async_trait]
pub trait MessageValidatorHandler: Send + Sync + 'static {
    /// Perform validation on the incoming message.
    ///
    /// Returns `Some(validated)` if the message should proceed to handling,
    /// or `None` to reject (the multiplexer will return `Ignore`).
    async fn validate(&self, msg: &IncomingMessage) -> Option<ValidatedMessage>;

    /// Handle a validated message.
    async fn handle(&self, msg: IncomingMessage, validated: ValidatedMessage) -> OutgoingMessage;
}

// ---------------------------------------------------------------------------
// Tagged handler wrappers
// ---------------------------------------------------------------------------

/// Pairs a [`Tag`] with a [`MessageHandler`] so the [`Multiplexer`] knows
/// which handler services which message type.
///
/// Mirrors Go's `network.TaggedMessageHandler`.
pub struct TaggedMessageHandler {
    /// The protocol tag this handler services.
    pub tag: Tag,
    /// The handler implementation.
    pub handler: Arc<dyn MessageHandler>,
}

/// Pairs a [`Tag`] with a [`MessageValidatorHandler`].
///
/// Mirrors Go's `network.TaggedMessageValidatorHandler`.
pub struct TaggedMessageValidatorHandler {
    /// The protocol tag this validator handler services.
    pub tag: Tag,
    /// The validator handler implementation.
    pub handler: Arc<dyn MessageValidatorHandler>,
}

// ---------------------------------------------------------------------------
// Multiplexer
// ---------------------------------------------------------------------------

/// Dispatches incoming messages to the handler registered for their [`Tag`].
///
/// Mirrors Go's `network.Multiplexer`.  Handlers are stored behind an
/// `RwLock` so that registration and clearing can happen concurrently with
/// dispatch.  During dispatch the `Arc` handler is cloned out of the read
/// lock, the lock is dropped, and then the handler is invoked — ensuring that
/// handler execution never holds the lock.
pub struct Multiplexer {
    handlers: RwLock<HashMap<Tag, Arc<dyn MessageHandler>>>,
    validator_handlers: RwLock<HashMap<Tag, Arc<dyn MessageValidatorHandler>>>,
    /// Early-message hold (issue #1987); see [`Multiplexer::with_early_hold`].
    early: Option<EarlyHold>,
}

/// Messages that arrive for a tag before its handler is registered.
///
/// go-algorand registers its agreement handlers before the network starts
/// listening, so nothing a peer sends at connect time is lost. algod-rust
/// starts the network first and builds the agreement service afterwards, and
/// a go peer replays its current round's votes and proposal the instant it
/// connects: those arrived a few milliseconds before the handlers existed and
/// were dropped, which left a node that started within seconds of its peer
/// waiting 60-120 s for the slow recovery steps (the p2p 1v1 soak stall).
/// Holding a bounded number of them for a short time, and delivering them in
/// order when the handler is registered, closes that window.
struct EarlyHold {
    tags: HashSet<Tag>,
    ttl: Duration,
    max_per_tag: usize,
    held: Mutex<HashMap<Tag, VecDeque<(Instant, IncomingMessage)>>>,
}

/// Default hold for [`Multiplexer::with_early_hold`]: how long a message
/// waits for its handler, and how many are kept per tag.
pub const EARLY_HOLD_TTL: Duration = Duration::from_secs(30);
pub const EARLY_HOLD_MAX_PER_TAG: usize = 128;

/// The agreement traffic tags worth holding for an agreement service that has
/// not started yet: votes, proposals and vote bundles.
pub const AGREEMENT_TAGS: [Tag; 3] = [Tag::AgreementVote, Tag::ProposalPayload, Tag::VoteBundle];

impl Default for Multiplexer {
    fn default() -> Self {
        Self::new()
    }
}

impl Multiplexer {
    /// Create an empty multiplexer with no handlers registered.
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
            validator_handlers: RwLock::new(HashMap::new()),
            early: None,
        }
    }

    /// A multiplexer that keeps the last `max_per_tag` messages (at most
    /// `ttl` old) for each of `tags` that arrive while no handler is
    /// registered for them, and delivers them, oldest first, as soon as a
    /// handler is. See [`EarlyHold`]. Messages are still reported as
    /// `Ignore` to the caller that received them early, exactly as without a
    /// hold.
    pub fn with_early_hold(tags: &[Tag], ttl: Duration, max_per_tag: usize) -> Self {
        let mut mux = Self::new();
        mux.early = Some(EarlyHold {
            tags: tags.iter().copied().collect(),
            ttl,
            max_per_tag,
            held: Mutex::new(HashMap::new()),
        });
        mux
    }

    /// Takes the held, still-fresh messages for `tag` (oldest first).
    fn take_held(&self, tag: Tag) -> Vec<IncomingMessage> {
        let Some(early) = &self.early else {
            return Vec::new();
        };
        let mut held = early.held.lock().expect("early hold lock poisoned");
        let Some(queue) = held.remove(&tag) else {
            return Vec::new();
        };
        let now = Instant::now();
        queue
            .into_iter()
            .filter(|(at, _)| now.duration_since(*at) <= early.ttl)
            .map(|(_, m)| m)
            .collect()
    }

    fn hold(&self, msg: &IncomingMessage) {
        let Some(early) = &self.early else { return };
        if !early.tags.contains(&msg.tag) || early.max_per_tag == 0 {
            return;
        }
        let mut held = early.held.lock().expect("early hold lock poisoned");
        let queue = held.entry(msg.tag).or_default();
        while queue.len() >= early.max_per_tag {
            queue.pop_front();
        }
        queue.push_back((Instant::now(), msg.clone()));
    }

    // -- Registration -------------------------------------------------------

    /// Register one or more message handlers.
    ///
    /// Each handler is keyed by its [`Tag`].  If a handler is already
    /// registered for a given tag *within the same batch*, this method panics
    /// (matching Go's behaviour).  Across separate calls the new handler
    /// overwrites the old one (last-write-wins).
    pub fn register_handlers(&self, handlers: Vec<TaggedMessageHandler>) {
        let mut to_replay: Vec<(Arc<dyn MessageHandler>, Vec<IncomingMessage>)> = Vec::new();
        {
            let mut map = self.handlers.write().expect("handler lock poisoned");
            for h in handlers {
                let held = self.take_held(h.tag);
                if !held.is_empty() {
                    to_replay.push((h.handler.clone(), held));
                }
                map.insert(h.tag, h.handler);
            }
        }
        // Deliver what arrived before the handler existed (in order, off the
        // caller's thread: `register_handlers` is synchronous, a handler is
        // async). Without a tokio runtime to run them on they are dropped,
        // which is what happened to them before the hold existed.
        for (handler, msgs) in to_replay {
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    for m in msgs {
                        let _ = handler.handle(m).await;
                    }
                });
            }
        }
    }

    /// Register one or more validator handlers.
    ///
    /// Semantics mirror [`register_handlers`](Self::register_handlers).
    pub fn register_validator_handlers(&self, handlers: Vec<TaggedMessageValidatorHandler>) {
        let mut map = self
            .validator_handlers
            .write()
            .expect("validator handler lock poisoned");
        for h in handlers {
            map.insert(h.tag, h.handler);
        }
    }

    // -- Clearing -----------------------------------------------------------

    /// Remove all handlers EXCEPT those whose tags are in `exclude_tags`.
    ///
    /// Mirrors Go's `ClearHandlers(excludeTags []Tag)` which clears all
    /// handlers other than those in the exclude list.  Pass an empty slice
    /// to clear everything.
    pub fn clear_handlers(&self, exclude_tags: &[Tag]) {
        let mut map = self.handlers.write().expect("handler lock poisoned");
        if exclude_tags.is_empty() {
            map.clear();
        } else {
            map.retain(|tag, _| exclude_tags.contains(tag));
        }
    }

    /// Remove all validator handlers EXCEPT those whose tags are in
    /// `exclude_tags`.
    ///
    /// Mirrors Go's `ClearValidatorHandlers(excludeTags []Tag)`.
    pub fn clear_validator_handlers(&self, exclude_tags: &[Tag]) {
        let mut map = self
            .validator_handlers
            .write()
            .expect("validator handler lock poisoned");
        if exclude_tags.is_empty() {
            map.clear();
        } else {
            map.retain(|tag, _| exclude_tags.contains(tag));
        }
    }

    // -- Dispatch -----------------------------------------------------------

    /// Dispatch a message to the handler registered for its tag.
    ///
    /// If no handler is registered for the tag, returns an [`OutgoingMessage`]
    /// with `action: Ignore`.
    ///
    /// The handler `Arc` is cloned out of the read lock before invocation so
    /// that handler execution never holds the lock.
    pub async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
        // Wire-level capture point (issue #497 debugging): enable with
        // `RUST_LOG=algo_network::wire=trace` to dump every incoming gossip
        // message's tag, origin peer, and raw payload hex for offline
        // decoding/diffing against go-algorand's encoder.
        tracing::trace!(
            target: "algo_network::wire",
            dir = "recv",
            tag = %msg.tag,
            peer = %msg.sender,
            len = msg.data.len(),
            hex = %hex_dump(&msg.data),
            "wire message"
        );
        let handler = {
            let map = self.handlers.read().expect("handler lock poisoned");
            map.get(&msg.tag).cloned()
        };

        match handler {
            Some(h) => h.handle(msg).await,
            None => {
                self.hold(&msg);
                OutgoingMessage {
                    action: ForwardingPolicy::Ignore,
                    tag: msg.tag,
                    payload: Vec::new(),
                    topics: None,
                }
            }
        }
    }

    /// Two-phase dispatch: validate then handle.
    ///
    /// First checks for a validator handler for the message's tag.  If found,
    /// calls `validate` — if validation returns `None`, returns `Ignore`.
    /// Otherwise calls `handle` with the validated state.
    ///
    /// If no validator handler is registered, falls through to the regular
    /// handler via [`handle`](Self::handle).
    pub async fn validate_handle(&self, msg: IncomingMessage) -> OutgoingMessage {
        let validator = {
            let map = self
                .validator_handlers
                .read()
                .expect("validator handler lock poisoned");
            map.get(&msg.tag).cloned()
        };

        match validator {
            Some(vh) => {
                let validated = vh.validate(&msg).await;
                match validated {
                    Some(v) => vh.handle(msg, v).await,
                    None => OutgoingMessage {
                        action: ForwardingPolicy::Ignore,
                        tag: msg.tag,
                        payload: Vec::new(),
                        topics: None,
                    },
                }
            }
            None => self.handle(msg).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// Simple handler that echoes the incoming data back with a Broadcast
    /// action and records invocation count.
    struct EchoHandler {
        call_count: AtomicUsize,
    }

    impl EchoHandler {
        fn new() -> Self {
            Self {
                call_count: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl MessageHandler for EchoHandler {
        async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            OutgoingMessage {
                action: ForwardingPolicy::Broadcast,
                tag: msg.tag,
                payload: msg.data.clone(),
                topics: None,
            }
        }
    }

    /// Handler that always responds with Disconnect.
    struct DisconnectHandler;

    #[async_trait]
    impl MessageHandler for DisconnectHandler {
        async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
            OutgoingMessage {
                action: ForwardingPolicy::Disconnect,
                tag: msg.tag,
                payload: Vec::new(),
                topics: None,
            }
        }
    }

    /// Validator handler that accepts messages with non-empty data.
    struct NonEmptyValidator {
        validate_count: AtomicUsize,
        handle_count: AtomicUsize,
    }

    impl NonEmptyValidator {
        fn new() -> Self {
            Self {
                validate_count: AtomicUsize::new(0),
                handle_count: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl MessageValidatorHandler for NonEmptyValidator {
        async fn validate(&self, msg: &IncomingMessage) -> Option<ValidatedMessage> {
            self.validate_count.fetch_add(1, Ordering::SeqCst);
            if msg.data.is_empty() {
                None
            } else {
                Some(ValidatedMessage(Box::new(msg.data.len())))
            }
        }

        async fn handle(
            &self,
            msg: IncomingMessage,
            validated: ValidatedMessage,
        ) -> OutgoingMessage {
            self.handle_count.fetch_add(1, Ordering::SeqCst);
            let len = *validated.0.downcast::<usize>().unwrap();
            OutgoingMessage {
                action: ForwardingPolicy::Accept,
                tag: msg.tag,
                payload: vec![len as u8],
                topics: None,
            }
        }
    }

    fn make_msg(tag: Tag, data: Vec<u8>) -> IncomingMessage {
        IncomingMessage::new(tag, data, "127.0.0.1:4160".to_string(), 0)
    }

    // -- Dispatch routes to correct handler by tag --------------------------

    #[tokio::test]
    async fn dispatch_routes_by_tag() {
        let mux = Multiplexer::new();
        let echo = Arc::new(EchoHandler::new());
        mux.register_handlers(vec![TaggedMessageHandler {
            tag: Tag::Transaction,
            handler: echo.clone(),
        }]);

        let msg = make_msg(Tag::Transaction, vec![1, 2, 3]);
        let out = mux.handle(msg).await;

        assert_eq!(out.action, ForwardingPolicy::Broadcast);
        assert_eq!(out.tag, Tag::Transaction);
        assert_eq!(out.payload, vec![1, 2, 3]);
        assert_eq!(echo.calls(), 1);
    }

    // -- Unknown tag returns Ignore -----------------------------------------

    #[tokio::test]
    async fn unknown_tag_returns_ignore() {
        let mux = Multiplexer::new();
        // Register a handler for Transaction but send a VoteBundle message.
        mux.register_handlers(vec![TaggedMessageHandler {
            tag: Tag::Transaction,
            handler: Arc::new(EchoHandler::new()),
        }]);

        let msg = make_msg(Tag::VoteBundle, vec![42]);
        let out = mux.handle(msg).await;

        assert_eq!(out.action, ForwardingPolicy::Ignore);
        assert_eq!(out.tag, Tag::VoteBundle);
    }

    // -- Register overwrites previous handler for same tag ------------------

    #[tokio::test]
    async fn register_overwrites_previous_handler() {
        let mux = Multiplexer::new();

        // First registration: echo handler
        mux.register_handlers(vec![TaggedMessageHandler {
            tag: Tag::AgreementVote,
            handler: Arc::new(EchoHandler::new()),
        }]);

        // Second registration: disconnect handler (overwrites)
        mux.register_handlers(vec![TaggedMessageHandler {
            tag: Tag::AgreementVote,
            handler: Arc::new(DisconnectHandler),
        }]);

        let msg = make_msg(Tag::AgreementVote, vec![1]);
        let out = mux.handle(msg).await;

        assert_eq!(out.action, ForwardingPolicy::Disconnect);
    }

    // -- Clear removes all handlers except excluded ---------------------------

    #[tokio::test]
    async fn clear_removes_all_except_excluded() {
        let mux = Multiplexer::new();
        mux.register_handlers(vec![
            TaggedMessageHandler {
                tag: Tag::Transaction,
                handler: Arc::new(EchoHandler::new()),
            },
            TaggedMessageHandler {
                tag: Tag::AgreementVote,
                handler: Arc::new(EchoHandler::new()),
            },
        ]);

        // Verify both work.
        let out = mux.handle(make_msg(Tag::Transaction, vec![1])).await;
        assert_eq!(out.action, ForwardingPolicy::Broadcast);
        let out = mux.handle(make_msg(Tag::AgreementVote, vec![1])).await;
        assert_eq!(out.action, ForwardingPolicy::Broadcast);

        // Clear all except AgreementVote.
        mux.clear_handlers(&[Tag::AgreementVote]);

        // Transaction should be gone (Ignore).
        let out = mux.handle(make_msg(Tag::Transaction, vec![1])).await;
        assert_eq!(out.action, ForwardingPolicy::Ignore);

        // AgreementVote should still work.
        let out = mux.handle(make_msg(Tag::AgreementVote, vec![1])).await;
        assert_eq!(out.action, ForwardingPolicy::Broadcast);
    }

    #[tokio::test]
    async fn clear_with_empty_removes_all() {
        let mux = Multiplexer::new();
        mux.register_handlers(vec![TaggedMessageHandler {
            tag: Tag::Transaction,
            handler: Arc::new(EchoHandler::new()),
        }]);

        // Verify it works first.
        let out = mux.handle(make_msg(Tag::Transaction, vec![1])).await;
        assert_eq!(out.action, ForwardingPolicy::Broadcast);

        // Clear all (empty exclude list).
        mux.clear_handlers(&[]);
        let out = mux.handle(make_msg(Tag::Transaction, vec![1])).await;
        assert_eq!(out.action, ForwardingPolicy::Ignore);
    }

    // -- Validator handler two-phase flow -----------------------------------

    #[tokio::test]
    async fn validator_two_phase_accept() {
        let mux = Multiplexer::new();
        let validator = Arc::new(NonEmptyValidator::new());
        mux.register_validator_handlers(vec![TaggedMessageValidatorHandler {
            tag: Tag::Transaction,
            handler: validator.clone(),
        }]);

        // Non-empty data: should pass validation and be handled.
        let msg = make_msg(Tag::Transaction, vec![0xAB, 0xCD]);
        let out = mux.validate_handle(msg).await;

        assert_eq!(out.action, ForwardingPolicy::Accept);
        assert_eq!(out.payload, vec![2]); // length of data
        assert_eq!(validator.validate_count.load(Ordering::SeqCst), 1);
        assert_eq!(validator.handle_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn validator_two_phase_reject() {
        let mux = Multiplexer::new();
        let validator = Arc::new(NonEmptyValidator::new());
        mux.register_validator_handlers(vec![TaggedMessageValidatorHandler {
            tag: Tag::Transaction,
            handler: validator.clone(),
        }]);

        // Empty data: validation should reject.
        let msg = make_msg(Tag::Transaction, vec![]);
        let out = mux.validate_handle(msg).await;

        assert_eq!(out.action, ForwardingPolicy::Ignore);
        assert_eq!(validator.validate_count.load(Ordering::SeqCst), 1);
        assert_eq!(validator.handle_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn validator_falls_through_to_regular_handler() {
        let mux = Multiplexer::new();

        // Register a regular handler but no validator handler.
        mux.register_handlers(vec![TaggedMessageHandler {
            tag: Tag::AgreementVote,
            handler: Arc::new(EchoHandler::new()),
        }]);

        let msg = make_msg(Tag::AgreementVote, vec![99]);
        let out = mux.validate_handle(msg).await;

        // Should fall through to the regular handler.
        assert_eq!(out.action, ForwardingPolicy::Broadcast);
        assert_eq!(out.payload, vec![99]);
    }

    // -- Multiple handlers for different tags work independently ------------

    #[tokio::test]
    async fn multiple_tags_independent() {
        let mux = Multiplexer::new();
        let echo = Arc::new(EchoHandler::new());
        let disc = Arc::new(DisconnectHandler);

        mux.register_handlers(vec![
            TaggedMessageHandler {
                tag: Tag::Transaction,
                handler: echo.clone(),
            },
            TaggedMessageHandler {
                tag: Tag::AgreementVote,
                handler: disc,
            },
        ]);

        let tx_out = mux.handle(make_msg(Tag::Transaction, vec![1])).await;
        let av_out = mux.handle(make_msg(Tag::AgreementVote, vec![2])).await;

        assert_eq!(tx_out.action, ForwardingPolicy::Broadcast);
        assert_eq!(av_out.action, ForwardingPolicy::Disconnect);
    }

    // -- Concurrent dispatch safety -----------------------------------------

    #[tokio::test]
    async fn concurrent_dispatch() {
        let mux = Arc::new(Multiplexer::new());
        let echo = Arc::new(EchoHandler::new());

        mux.register_handlers(vec![TaggedMessageHandler {
            tag: Tag::Transaction,
            handler: echo.clone(),
        }]);

        let mut tasks = Vec::new();
        for i in 0u8..20 {
            let mux = mux.clone();
            tasks.push(tokio::spawn(async move {
                let msg = make_msg(Tag::Transaction, vec![i]);
                let out = mux.handle(msg).await;
                assert_eq!(out.action, ForwardingPolicy::Broadcast);
                assert_eq!(out.payload, vec![i]);
            }));
        }

        for task in tasks {
            task.await.unwrap();
        }

        assert_eq!(echo.calls(), 20);
    }

    // -- Clear validator handlers -------------------------------------------

    #[tokio::test]
    async fn clear_validator_handlers_removes_all_except_excluded() {
        let mux = Multiplexer::new();
        mux.register_validator_handlers(vec![TaggedMessageValidatorHandler {
            tag: Tag::Transaction,
            handler: Arc::new(NonEmptyValidator::new()),
        }]);

        // Should be handled by validator.
        let out = mux
            .validate_handle(make_msg(Tag::Transaction, vec![1]))
            .await;
        assert_eq!(out.action, ForwardingPolicy::Accept);

        // Clear all (empty exclude list) and verify fallthrough to no handler (Ignore).
        mux.clear_validator_handlers(&[]);
        let out = mux
            .validate_handle(make_msg(Tag::Transaction, vec![1]))
            .await;
        assert_eq!(out.action, ForwardingPolicy::Ignore);
    }

    // -- Default trait -------------------------------------------------------

    #[test]
    fn multiplexer_default() {
        let mux = Multiplexer::default();
        // Should have empty handler maps; just verify no panic.
        assert!(mux
            .handlers
            .read()
            .expect("handler lock poisoned")
            .is_empty());
        assert!(mux
            .validator_handlers
            .read()
            .expect("validator handler lock poisoned")
            .is_empty());
    }

    // -- Concurrent registration and dispatch --------------------------------

    #[tokio::test]
    async fn concurrent_register_and_dispatch() {
        let mux = Arc::new(Multiplexer::new());

        // Register initial handler.
        mux.register_handlers(vec![TaggedMessageHandler {
            tag: Tag::Transaction,
            handler: Arc::new(EchoHandler::new()),
        }]);

        let mux_dispatch = mux.clone();
        let mux_register = mux.clone();

        // Spawn dispatch tasks.
        let dispatch_task = tokio::spawn(async move {
            for _ in 0..10 {
                let msg = make_msg(Tag::Transaction, vec![1]);
                let out = mux_dispatch.handle(msg).await;
                // Could be either echo or disconnect depending on timing.
                assert!(
                    out.action == ForwardingPolicy::Broadcast
                        || out.action == ForwardingPolicy::Disconnect
                );
            }
        });

        // Spawn registration task that overwrites the handler mid-flight.
        let register_task = tokio::spawn(async move {
            for _ in 0..5 {
                mux_register.register_handlers(vec![TaggedMessageHandler {
                    tag: Tag::Transaction,
                    handler: Arc::new(DisconnectHandler),
                }]);
            }
        });

        dispatch_task.await.unwrap();
        register_task.await.unwrap();
    }

    // ── Issue #1987: early-message hold ───────────────────────────────────
    fn msg(tag: Tag, n: u8) -> IncomingMessage {
        IncomingMessage::new(tag, vec![n], "peer".to_string(), 0)
    }

    /// Records the payload byte of every message it handles.
    struct Recorder(Mutex<Vec<u8>>);

    #[async_trait]
    impl MessageHandler for Recorder {
        async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
            self.0.lock().unwrap().push(msg.data[0]);
            OutgoingMessage {
                action: ForwardingPolicy::Ignore,
                tag: msg.tag,
                payload: Vec::new(),
                topics: None,
            }
        }
    }

    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    #[tokio::test]
    async fn early_messages_are_delivered_in_order_once_the_handler_exists() {
        let mux = Multiplexer::with_early_hold(
            &[Tag::AgreementVote],
            Duration::from_secs(30),
            128,
        );
        for n in 1..=3 {
            let out = mux.handle(msg(Tag::AgreementVote, n)).await;
            assert_eq!(out.action, ForwardingPolicy::Ignore, "still ignored for the caller");
        }
        let rec = Arc::new(Recorder(Mutex::new(Vec::new())));
        mux.register_handlers(vec![TaggedMessageHandler {
            tag: Tag::AgreementVote,
            handler: rec.clone(),
        }]);
        settle().await;
        assert_eq!(*rec.0.lock().unwrap(), vec![1, 2, 3]);
        // delivered once, not again on a later registration
        mux.register_handlers(vec![TaggedMessageHandler {
            tag: Tag::AgreementVote,
            handler: rec.clone(),
        }]);
        settle().await;
        assert_eq!(rec.0.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn only_the_configured_tags_are_held() {
        let mux = Multiplexer::with_early_hold(&[Tag::AgreementVote], Duration::from_secs(30), 8);
        mux.handle(msg(Tag::Transaction, 9)).await;
        let rec = Arc::new(Recorder(Mutex::new(Vec::new())));
        mux.register_handlers(vec![TaggedMessageHandler { tag: Tag::Transaction, handler: rec.clone() }]);
        settle().await;
        assert!(rec.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_hold_is_bounded_and_keeps_the_newest() {
        let mux = Multiplexer::with_early_hold(&[Tag::AgreementVote], Duration::from_secs(30), 2);
        for n in 1..=5 {
            mux.handle(msg(Tag::AgreementVote, n)).await;
        }
        let rec = Arc::new(Recorder(Mutex::new(Vec::new())));
        mux.register_handlers(vec![TaggedMessageHandler { tag: Tag::AgreementVote, handler: rec.clone() }]);
        settle().await;
        assert_eq!(*rec.0.lock().unwrap(), vec![4, 5]);
    }

    #[tokio::test]
    async fn stale_early_messages_are_not_delivered() {
        let mux = Multiplexer::with_early_hold(&[Tag::AgreementVote], Duration::from_millis(10), 8);
        mux.handle(msg(Tag::AgreementVote, 1)).await;
        tokio::time::sleep(Duration::from_millis(40)).await;
        let rec = Arc::new(Recorder(Mutex::new(Vec::new())));
        mux.register_handlers(vec![TaggedMessageHandler { tag: Tag::AgreementVote, handler: rec.clone() }]);
        settle().await;
        assert!(rec.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_plain_multiplexer_holds_nothing() {
        let mux = Multiplexer::new();
        mux.handle(msg(Tag::AgreementVote, 1)).await;
        let rec = Arc::new(Recorder(Mutex::new(Vec::new())));
        mux.register_handlers(vec![TaggedMessageHandler { tag: Tag::AgreementVote, handler: rec.clone() }]);
        settle().await;
        assert!(rec.0.lock().unwrap().is_empty());
    }

}
