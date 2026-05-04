// Deterministic agreement fuzzer harness.
//
// Mirrors the structure of go-algorand/agreement/fuzzer/ — a deterministic
// adversarial network simulator that pumps protocol messages through a
// chain of `Filter` implementations and routes them to peer nodes.
//
// Despite the "fuzzer" name, this harness is *not* RNG-driven; like Go's
// version it uses counter-based filter logic so that a given filter
// configuration always produces the same delivery sequence. That keeps
// failures reproducible from the recorded scenario alone.
//
// Module map (mirrors go-algorand/agreement/fuzzer/):
//   * `filter`          — `Filter` trait + `FilterDecision` enum
//   * `network_facade`  — per-node send/receive entry point that runs the
//                         outgoing / incoming filter chains and applies
//                         their decisions (keep / drop / duplicate / delay)
//   * `router`          — broadcast/relay routing across the cluster
//   * `scheduler`       — top-level tick driver that owns the cluster and
//                         pumps each node's `Tick` and `tick` deliveries
//   * `filters::drop_message`      — drop every Nth message
//   * `filters::duplicate_message` — re-deliver every Nth message N+1 times
//
// Public API: see [`scheduler::Scheduler`] for the harness entry point and
// [`AlgoMessage`] for the in-flight message envelope.
//
// Out of scope (deferred to follow-up tasks):
//   * Live multi-Service integration. This iteration ships the message-
//     plumbing harness and unit-tests the filters via deterministic
//     scenarios; binding the harness to N real `Service` instances over
//     a custom `AgreementNetwork` impl is TASK-85 / Phase 6 mixed-cluster
//     work.
//   * Reorder, nodeCrash, bandwidth, message-delay, regossip filters.
//   * RNG-driven scenario generation.

#![allow(dead_code)] // Some of the message-routing helpers are exercised
                     // only via the integration smoke test in
                     // `tests/fuzzer_smoke.rs`; keeping them unconditional
                     // avoids the cfg(test) hot-loop that the simulate
                     // sibling crate uses.

pub mod filter;
pub mod filters;
pub mod network_facade;
pub mod router;
pub mod scheduler;

use std::cmp::Ordering;

/// A single in-flight protocol message routed through the fuzzer.
///
/// Matches go-algorand's `AlgoMessage` envelope (`agreement/fuzzer/`) —
/// a copy of the payload bytes plus addressing metadata. We keep it
/// `Clone` because the `Duplicate` filter decision needs to emit fresh
/// copies, and there's no shared mutability across the chain so the
/// extra allocation is tolerable for test workloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlgoMessage {
    /// 0-based index of the node that produced this message.
    pub source_node: usize,
    /// 0-based index of the receiving node, or `None` for a broadcast
    /// destined for every peer (mirrors Go's `targetNode = -1` sentinel).
    pub target_node: Option<usize>,
    /// Protocol tag — the same string the production network uses
    /// (`AGREEMENT_VOTE_TAG`, `PROPOSAL_PAYLOAD_TAG`, `VOTE_BUNDLE_TAG`).
    pub tag: String,
    /// Raw codec-encoded payload.
    pub data: Vec<u8>,
}

impl AlgoMessage {
    /// Construct a directed unicast message.
    pub fn unicast(source: usize, target: usize, tag: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            source_node: source,
            target_node: Some(target),
            tag: tag.into(),
            data,
        }
    }

    /// Construct a broadcast (no specific target).
    pub fn broadcast(source: usize, tag: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            source_node: source,
            target_node: None,
            tag: tag.into(),
            data,
        }
    }
}

/// A message scheduled to fire at a future tick.
///
/// Used by the `Delay { delay_ticks }` filter decision (and any future
/// filters that emit delayed traffic via `Filter::tick`). Stored in the
/// network facade's per-direction min-heap, so we order by `release_tick`
/// ascending — the standard `BinaryHeap` is a max-heap, hence the
/// inverted comparison below.
#[derive(Clone, Debug)]
pub struct DelayedMessage {
    pub release_tick: u64,
    /// Sequence number of the original `enqueue` call. Used purely as a
    /// tie-breaker so identical-tick messages keep insertion order, which
    /// is what go-algorand's heap with stable ordering achieves implicitly.
    pub sequence: u64,
    pub message: AlgoMessage,
}

impl PartialEq for DelayedMessage {
    fn eq(&self, other: &Self) -> bool {
        self.release_tick == other.release_tick && self.sequence == other.sequence
    }
}

impl Eq for DelayedMessage {}

impl Ord for DelayedMessage {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse so `BinaryHeap` (max-heap) yields the *earliest*
        // release_tick first. Tie-break on `sequence` ascending so two
        // messages with the same release tick fire in insertion order.
        other
            .release_tick
            .cmp(&self.release_tick)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

impl PartialOrd for DelayedMessage {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
