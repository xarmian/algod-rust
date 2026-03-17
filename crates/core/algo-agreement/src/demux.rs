// Async event multiplexer for the agreement protocol.
//
// Mirrors go-algorand/agreement/demux.go.
//
// The Demux supplies the state machine with the next relevant external input
// event. It multiplexes events from multiple sources:
//   - Network messages (votes, proposals, bundles)
//   - Timeout events (filter, deadline, fast recovery)
//   - Verification results (async vote/payload/bundle verification completions)
//   - Round interruptions from the ledger
//   - Pseudonode events (locally generated proposals/votes)
//
// This Rust implementation uses tokio channels for async multiplexing.

use algo_types::Round;

use crate::events::{
    ConsensusVersionView, Event, EventType, MessageEvent, RoundInterruptionEvent, TimeoutEvent,
};
use crate::types::Deadline;

// ---------------------------------------------------------------------------
// Event queue names (for monitoring)
// ---------------------------------------------------------------------------

/// Queue name for the demux itself.
pub const EVENT_QUEUE_DEMUX: &str = "demux";
/// Queue name for the crypto verifier vote results.
pub const EVENT_QUEUE_CRYPTO_VERIFIER_VOTE: &str = "cryptoVerifierVote";
/// Queue name for the crypto verifier proposal results.
pub const EVENT_QUEUE_CRYPTO_VERIFIER_PROPOSAL: &str = "cryptoVerifierProposal";
/// Queue name for the crypto verifier bundle results.
pub const EVENT_QUEUE_CRYPTO_VERIFIER_BUNDLE: &str = "cryptoVerifierBundle";
/// Queue name for pseudonode events.
pub const EVENT_QUEUE_PSEUDONODE: &str = "pseudonode";

// ---------------------------------------------------------------------------
// ExternalEvent
// ---------------------------------------------------------------------------

/// An external event to be delivered to the state machine.
///
/// Wraps an `Event` along with metadata about its source and consensus version.
#[derive(Debug, Clone)]
pub struct ExternalEvent {
    /// The underlying event.
    pub event: Event,
}

impl ExternalEvent {
    /// Returns the event type.
    pub fn event_type(&self) -> EventType {
        self.event.event_type()
    }

    /// Returns the consensus round for this event.
    pub fn consensus_round(&self) -> Round {
        match &self.event {
            Event::Message(me) => me.consensus_round(),
            Event::FilterableMessage(fme) => fme.message_event.consensus_round(),
            Event::RoundInterruption(rie) => rie.consensus_round(),
            Event::Timeout(te) => te.consensus_round(),
            _ => Round(0),
        }
    }

    /// Returns a new ExternalEvent with the consensus version attached.
    pub fn attach_consensus_version(mut self, v: ConsensusVersionView) -> Self {
        match &mut self.event {
            Event::Message(me) => {
                me.proto = v;
            }
            Event::RoundInterruption(rie) => {
                rie.proto = v;
            }
            Event::Timeout(te) => {
                te.proto = v;
            }
            _ => {}
        }
        self
    }
}

// ---------------------------------------------------------------------------
// ExternalDemuxSignals
// ---------------------------------------------------------------------------

/// Signals used to synchronize the external signals that go to the demux with
/// the main loop.
///
/// Mirrors Go's `externalDemuxSignals`.
#[derive(Debug, Clone)]
pub struct ExternalDemuxSignals {
    /// The current player deadline.
    pub deadline: Deadline,
    /// The fast recovery deadline.
    pub fast_recovery_deadline: Deadline,
    /// The current round.
    pub current_round: Round,
}

// ---------------------------------------------------------------------------
// Demux
// ---------------------------------------------------------------------------

/// The demultiplexer for the agreement state machine.
///
/// Supplies the state machine with the next relevant external input event,
/// multiplexing events from network, crypto verification, timeouts, and the
/// ledger.
///
/// Unlike the Go implementation which uses goroutines and select statements,
/// this Rust implementation provides a synchronous `next()` method that can
/// be called in a loop. The actual async channel integration will be added
/// when the full service infrastructure is in place.
///
/// Mirrors Go's `demux`.
#[derive(Debug, Clone, Default)]
pub struct Demux {
    /// Priority queue of pseudonode event channels.
    /// Events from these channels are delivered before other events.
    queue: Vec<Vec<ExternalEvent>>,

    /// Current position in the priority queue (first non-empty channel).
    queue_pos: usize,

    /// Pending events from various sources that have been pre-staged.
    /// This allows the demux to buffer events from multiple sources.
    pending_events: Vec<ExternalEvent>,
}

impl Demux {
    /// Create a new demux.
    ///
    /// Mirrors Go's `makeDemux`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a channel of events to deliver ahead of other input.
    ///
    /// If the source has a limited amount of input, the caller should ensure
    /// all events are included. The demux will process queued channels in FIFO
    /// order before returning to other event sources.
    ///
    /// Mirrors Go's `demux.prioritize`.
    pub fn prioritize(&mut self, events: Vec<ExternalEvent>) {
        self.queue.push(events);
    }

    /// Stage a pending event from an external source (network, crypto, etc.).
    ///
    /// These events are returned by `next()` after any priority queue events.
    pub fn stage_event(&mut self, event: ExternalEvent) {
        self.pending_events.push(event);
    }

    /// Returns the next event to process.
    ///
    /// Priority order:
    /// 1. Pseudonode events from the priority queue
    /// 2. Pending events from other sources
    /// 3. Timeout events (generated from deadline information)
    ///
    /// Returns `None` if there are no events and the demux should quit.
    ///
    /// Mirrors Go's `demux.next`.
    pub fn next(
        &mut self,
        _deadline: &Deadline,
        _fast_deadline: &Deadline,
        _current_round: Round,
    ) -> Option<ExternalEvent> {
        // First, drain priority queue events (FIFO order)
        while self.queue_pos < self.queue.len() {
            let channel = &mut self.queue[self.queue_pos];
            if !channel.is_empty() {
                return Some(channel.remove(0));
            }
            // Channel exhausted, move to next
            self.queue_pos += 1;
        }
        // Clear exhausted channels
        if self.queue_pos > 0 {
            self.queue.drain(..self.queue_pos);
            self.queue_pos = 0;
        }

        // Next, return pending events
        if !self.pending_events.is_empty() {
            return Some(self.pending_events.remove(0));
        }

        // If no events are pending, this is where the Go implementation would
        // block in a select statement waiting for:
        //   - rawVotes, rawProposals, rawBundles (network)
        //   - crypto.VerifiedVotes(), crypto.Verified(tag) (verification)
        //   - ledgerNextRoundCh (ledger)
        //   - deadlineCh, fastDeadlineCh (timeouts)
        //   - s.quit (shutdown)
        //
        // In this synchronous Rust implementation, we return None to indicate
        // no events are currently available. The caller (service loop) is
        // responsible for feeding events via stage_event() or prioritize().
        None
    }

    /// Shut down the demux.
    ///
    /// Mirrors Go's `demux.quit`.
    pub fn quit(&mut self) {
        self.queue.clear();
        self.queue_pos = 0;
        self.pending_events.clear();
    }

    /// Returns the number of pending events across all sources.
    pub fn pending_count(&self) -> usize {
        let queue_count: usize = self
            .queue
            .iter()
            .skip(self.queue_pos)
            .map(|c| c.len())
            .sum();
        queue_count + self.pending_events.len()
    }
}

// ---------------------------------------------------------------------------
// Helper: setupCompoundMessage
// ---------------------------------------------------------------------------

/// Process compound messages: distinct messages which are delivered together.
///
/// A compound message from the network may contain both a proposal payload
/// and a proposal-vote. This function splits them into the appropriate event
/// types.
///
/// Mirrors Go's `setupCompoundMessage`.
pub fn setup_compound_message(
    vote_present: bool,
    payload_event: MessageEvent,
    vote_event: Option<MessageEvent>,
) -> ExternalEvent {
    if !vote_present {
        // No vote attached: just a payload
        ExternalEvent {
            event: Event::Message(payload_event),
        }
    } else {
        // Vote + payload: vote is primary, payload is the tail
        let mut ve = vote_event.unwrap_or_default();
        ve.tail = Some(Box::new(payload_event));
        ExternalEvent {
            event: Event::Message(ve),
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: make timeout events
// ---------------------------------------------------------------------------

/// Create a regular timeout event.
pub fn make_timeout_event(random_entropy: u64, round: Round) -> ExternalEvent {
    ExternalEvent {
        event: Event::Timeout(TimeoutEvent {
            t: EventType::Timeout,
            random_entropy,
            round,
            proto: ConsensusVersionView::default(),
        }),
    }
}

/// Create a fast timeout event.
pub fn make_fast_timeout_event(random_entropy: u64, round: Round) -> ExternalEvent {
    ExternalEvent {
        event: Event::Timeout(TimeoutEvent {
            t: EventType::FastTimeout,
            random_entropy,
            round,
            proto: ConsensusVersionView::default(),
        }),
    }
}

/// Create a round interruption event.
pub fn make_round_interruption_event(round: Round) -> ExternalEvent {
    ExternalEvent {
        event: Event::RoundInterruption(RoundInterruptionEvent {
            round,
            proto: ConsensusVersionView::default(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EmptyEvent;

    #[test]
    fn demux_default() {
        let d = Demux::default();
        assert_eq!(d.pending_count(), 0);
    }

    #[test]
    fn demux_stage_and_next() {
        let mut d = Demux::new();
        let event = ExternalEvent {
            event: Event::Empty(EmptyEvent),
        };
        d.stage_event(event);
        assert_eq!(d.pending_count(), 1);

        let deadline = Deadline::default();
        let fast_deadline = Deadline::default();
        let result = d.next(&deadline, &fast_deadline, Round(1));
        assert!(result.is_some());
        assert_eq!(d.pending_count(), 0);
    }

    #[test]
    fn demux_prioritize() {
        let mut d = Demux::new();

        // Stage a regular event
        d.stage_event(ExternalEvent {
            event: Event::Timeout(TimeoutEvent {
                t: EventType::Timeout,
                ..TimeoutEvent::default()
            }),
        });

        // Prioritize events should come first
        d.prioritize(vec![ExternalEvent {
            event: Event::Empty(EmptyEvent),
        }]);

        let deadline = Deadline::default();
        let fast_deadline = Deadline::default();

        // First call should return the priority event
        let result = d.next(&deadline, &fast_deadline, Round(1));
        assert!(result.is_some());
        assert_eq!(result.unwrap().event_type(), EventType::None);

        // Second call should return the staged event
        let result = d.next(&deadline, &fast_deadline, Round(1));
        assert!(result.is_some());
        assert_eq!(result.unwrap().event_type(), EventType::Timeout);
    }

    #[test]
    fn demux_next_empty() {
        let mut d = Demux::new();
        let deadline = Deadline::default();
        let fast_deadline = Deadline::default();
        let result = d.next(&deadline, &fast_deadline, Round(1));
        assert!(result.is_none());
    }

    #[test]
    fn demux_quit() {
        let mut d = Demux::new();
        d.stage_event(ExternalEvent {
            event: Event::Empty(EmptyEvent),
        });
        d.prioritize(vec![ExternalEvent {
            event: Event::Empty(EmptyEvent),
        }]);
        assert!(d.pending_count() > 0);

        d.quit();
        assert_eq!(d.pending_count(), 0);
    }

    #[test]
    fn make_timeout_event_type() {
        let e = make_timeout_event(42, Round(1));
        assert_eq!(e.event_type(), EventType::Timeout);
    }

    #[test]
    fn make_fast_timeout_event_type() {
        let e = make_fast_timeout_event(42, Round(1));
        assert_eq!(e.event_type(), EventType::FastTimeout);
    }

    #[test]
    fn make_round_interruption_event_type() {
        let e = make_round_interruption_event(Round(5));
        assert_eq!(e.event_type(), EventType::RoundInterruption);
    }

    #[test]
    fn external_event_consensus_round() {
        let e = make_round_interruption_event(Round(42));
        assert_eq!(e.consensus_round(), Round(42));
    }
}
