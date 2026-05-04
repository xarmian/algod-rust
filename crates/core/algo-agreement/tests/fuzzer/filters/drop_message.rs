// `DropMessageFilter` — drops every Nth message in either direction.
//
// Mirrors `agreement/fuzzer/dropMessageFilter_test.go` (Go) — the
// behavior is *deterministic*, not RNG-driven: the filter keeps two
// counters (one per direction) and drops the message whenever
// `counter % rate == 0` after incrementing. `rate == 0` is treated as
// "drop everything" (matches Go's `rate == 0` short-circuit).
//
// Per-direction rates can be configured independently via
// [`DropMessageFilterBuilder`]; either can be `None` (default — pass
// everything through in that direction).

use crate::fuzzer::filter::{Filter, FilterDecision};
use crate::fuzzer::AlgoMessage;

/// Builder that produces [`DropMessageFilter`] instances configured
/// for a particular `(outgoing_rate, incoming_rate)` pair.
#[derive(Clone, Debug, Default)]
pub struct DropMessageFilterBuilder {
    outgoing_rate: Option<u64>,
    incoming_rate: Option<u64>,
}

impl DropMessageFilterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop every Nth outgoing message. `Some(0)` ⇒ drop every message;
    /// `Some(N)` for `N > 0` ⇒ drop the Nth, 2Nth, 3Nth, … message.
    /// `None` ⇒ pass all outgoing messages through.
    pub fn outgoing_rate(mut self, rate: Option<u64>) -> Self {
        self.outgoing_rate = rate;
        self
    }

    /// Drop every Nth incoming message — same semantics as
    /// [`Self::outgoing_rate`] but for traffic arriving at this node.
    pub fn incoming_rate(mut self, rate: Option<u64>) -> Self {
        self.incoming_rate = rate;
        self
    }

    pub fn build(self) -> DropMessageFilter {
        DropMessageFilter {
            outgoing_rate: self.outgoing_rate,
            incoming_rate: self.incoming_rate,
            outgoing_seen: 0,
            incoming_seen: 0,
        }
    }
}

/// Per-node drop filter. See module-level doc for semantics.
pub struct DropMessageFilter {
    outgoing_rate: Option<u64>,
    incoming_rate: Option<u64>,
    outgoing_seen: u64,
    incoming_seen: u64,
}

impl DropMessageFilter {
    /// Number of outgoing messages observed (kept + dropped).
    pub fn outgoing_seen(&self) -> u64 {
        self.outgoing_seen
    }

    /// Number of incoming messages observed (kept + dropped).
    pub fn incoming_seen(&self) -> u64 {
        self.incoming_seen
    }
}

impl Filter for DropMessageFilter {
    fn name(&self) -> &str {
        "DropMessageFilter"
    }

    fn filter_outgoing(&mut self, _msg: &AlgoMessage) -> FilterDecision {
        self.outgoing_seen = self.outgoing_seen.wrapping_add(1);
        decide(self.outgoing_seen, self.outgoing_rate)
    }

    fn filter_incoming(&mut self, _msg: &AlgoMessage) -> FilterDecision {
        self.incoming_seen = self.incoming_seen.wrapping_add(1);
        decide(self.incoming_seen, self.incoming_rate)
    }
}

fn decide(counter: u64, rate: Option<u64>) -> FilterDecision {
    match rate {
        None => FilterDecision::Keep,
        // Match Go's semantics: `rate == 0` means "drop every message".
        // `dropMessageFilter_test.go:48-52`: `if rate == 0 || n.sendMessageCount%rate != 0 { ... downstream.SendMessage(...) }`
        // — the body forwards the message when the modulus is non-zero
        // OR when rate==0 (the latter SHORT-CIRCUITING TO DROP because
        // the surrounding `if rate, has := ...; has { ... return }` then
        // suppresses the fallback). Net effect: rate==0 drops all.
        // Easier to read in Rust as an explicit branch.
        Some(0) => FilterDecision::Drop,
        Some(rate) => {
            if counter % rate == 0 {
                FilterDecision::Drop
            } else {
                FilterDecision::Keep
            }
        }
    }
}
