// `NodeCrashFilter` — simulates a crashed node by suppressing all
// traffic in BOTH directions during a configured tick range.
//
// Conceptually mirrors `agreement/fuzzer/nodeCrashFilter_test.go`,
// but with a different shape that fits the existing Filter trait
// without giving filters a back-reference to the scheduler. Where
// Go's filter calls `n.fuzzer.CrashNode(n.nodeID)` from `Tick(...)`
// to mutate the cluster from inside a filter, this Rust port models
// "node N is crashed during ticks [start, end)" as a per-message
// short-circuit in `filter_outgoing` / `filter_incoming` that
// returns `Drop` whenever the harness's clock falls inside the
// crash window.
//
// The TASK-85 acceptance criterion calls this out as the desired
// semantic: "disables a player for a configured round range; player
// rejoins in a later round." Translating "round range" to "tick
// range" is straightforward because the harness clock is the only
// time reference available to filters.
//
// # Known limitation: delayed-message bypass
//
// Messages that another filter in the chain (e.g. a future
// `MessageDelayFilter`) parked in the [`NetworkFacade`]'s delay heap
// BEFORE the crash window started will still be released during the
// crash window — the scheduler's `tick_to` releases them directly
// to the router without re-entering the source's outgoing chain
// (matching Go's `processDownstreamBuffer` semantics, see
// `agreement/fuzzer/messageDuplicationFilter_test.go:154`). For a
// strictly-correct "crashed node emits nothing" model, place
// `NodeCrashFilter` **first** in the outgoing chain and avoid
// combining it with `Delay`-emitting filters until the multi-Service
// follow-up plumbs an `is_crashed()` veto through the scheduler. The
// test
// `node_crash_filter_documents_delay_release_bypass_known_limitation`
// in `fuzzer_smoke.rs` locks down the current behavior so a future
// fix can flip the assertion intentionally.
//
// Determinism: the filter is purely deterministic — the crash window
// is configured up front; no RNG involved. Same configuration ⇒
// same suppression sequence.

use crate::fuzzer::filter::{Filter, FilterDecision};
use crate::fuzzer::AlgoMessage;

/// Builder for [`NodeCrashFilter`]. The crash window is inclusive
/// of `start_tick` and exclusive of `end_tick` — i.e. `[start, end)`.
/// `start_tick == end_tick` ⇒ no crash. `end_tick == u64::MAX` ⇒
/// "permanently crashed once start_tick is reached".
#[derive(Clone, Debug, Default)]
pub struct NodeCrashFilterBuilder {
    crash_start_tick: u64,
    crash_end_tick: u64,
}

impl NodeCrashFilterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure a `[start, end)` crash window. While `start <=
    /// current_tick < end` the filter drops every message in BOTH
    /// directions.
    ///
    /// Panics if `start > end` — that's a harness configuration bug.
    pub fn crash_window(mut self, start_tick: u64, end_tick: u64) -> Self {
        assert!(
            start_tick <= end_tick,
            "NodeCrashFilter: crash window start ({start_tick}) must be <= end ({end_tick})",
        );
        self.crash_start_tick = start_tick;
        self.crash_end_tick = end_tick;
        self
    }

    pub fn build(self) -> NodeCrashFilter {
        NodeCrashFilter {
            crash_start_tick: self.crash_start_tick,
            crash_end_tick: self.crash_end_tick,
            current_tick: 0,
            crashed_messages_seen: 0,
        }
    }
}

/// Per-node crash filter. See module doc for semantics.
pub struct NodeCrashFilter {
    crash_start_tick: u64,
    crash_end_tick: u64,
    current_tick: u64,
    crashed_messages_seen: u64,
}

impl NodeCrashFilter {
    fn is_crashed(&self) -> bool {
        self.current_tick >= self.crash_start_tick && self.current_tick < self.crash_end_tick
    }

    /// Number of messages this filter has dropped because the node
    /// was crashed at the time of arrival. Useful for assertion in
    /// unit tests.
    pub fn crashed_messages_seen(&self) -> u64 {
        self.crashed_messages_seen
    }
}

impl Filter for NodeCrashFilter {
    fn name(&self) -> &str {
        "NodeCrashFilter"
    }

    fn filter_outgoing(&mut self, _msg: &AlgoMessage) -> FilterDecision {
        if self.is_crashed() {
            self.crashed_messages_seen = self.crashed_messages_seen.wrapping_add(1);
            FilterDecision::Drop
        } else {
            FilterDecision::Keep
        }
    }

    fn filter_incoming(&mut self, _msg: &AlgoMessage) -> FilterDecision {
        if self.is_crashed() {
            self.crashed_messages_seen = self.crashed_messages_seen.wrapping_add(1);
            FilterDecision::Drop
        } else {
            FilterDecision::Keep
        }
    }

    /// Track the cluster clock so `is_crashed` reflects the current
    /// tick. The filter never spontaneously emits messages.
    fn tick(&mut self, new_clock_time: u64) -> Vec<AlgoMessage> {
        self.current_tick = new_clock_time;
        Vec::new()
    }
}
