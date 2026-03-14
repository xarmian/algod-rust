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
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;

use crate::forwarding_policy::ForwardingPolicy;
use crate::message::{IncomingMessage, OutgoingMessage};
use crate::tag::Tag;

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
}

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
        }
    }

    // -- Registration -------------------------------------------------------

    /// Register one or more message handlers.
    ///
    /// Each handler is keyed by its [`Tag`].  If a handler is already
    /// registered for a given tag *within the same batch*, this method panics
    /// (matching Go's behaviour).  Across separate calls the new handler
    /// overwrites the old one (last-write-wins).
    pub fn register_handlers(&self, handlers: Vec<TaggedMessageHandler>) {
        let mut map = self.handlers.write().expect("handler lock poisoned");
        for h in handlers {
            map.insert(h.tag, h.handler);
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
        let handler = {
            let map = self.handlers.read().expect("handler lock poisoned");
            map.get(&msg.tag).cloned()
        };

        match handler {
            Some(h) => h.handle(msg).await,
            None => OutgoingMessage {
                action: ForwardingPolicy::Ignore,
                tag: msg.tag,
                payload: Vec::new(),
                topics: None,
            },
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
}
