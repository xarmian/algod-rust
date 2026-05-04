// `MessageReorderingFilter` — buffers a small per-direction pool of
// in-flight messages and emits them out-of-insertion-order under a
// seeded RNG. Mirrors `agreement/fuzzer/messageReorderingFilter_test.go`.
//
// Behavior (per direction, configurable independently):
//   * `shuffle_size == 0` ⇒ no reordering; every message passes
//     through unchanged.
//   * `shuffle_size == N > 0` ⇒
//      1. Every observed message is appended to the pool.
//      2. While `pool.len() <= N`, the message is HELD (the filter
//         returns `Drop`); the harness gets nothing this call.
//      3. Once `pool.len() > N`, the filter picks a uniformly-random
//         index and emits THAT message in place of the current
//         arrival via `FilterDecision::Substitute { with: vec![picked] }`.
//         The picked message could be the just-arrived one (no
//         reordering effect for that arrival) or any older pool
//         resident (effective swap).
//
// This matches Go's `MessageReorderingFilter::SendMessage` semantics
// from `agreement/fuzzer/messageReorderingFilter_test.go:70-99` —
// just expressed without a back-channel because Rust's
// `FilterDecision::Substitute` lets us swap inline.
//
// Determinism: each direction has its own seeded `StdRng`. The same
// seed always produces the same sequence of `(pool_size, idx)` picks
// across reruns — that's the "deterministic under seeded RNG"
// guarantee from the TASK-85 acceptance criteria.
//
// Drainage: anything still in the pool at end-of-test stays parked.
// Tests that need to assert "no message lost" call
// [`MessageReorderingFilter::drain_pending`] to flush the pools
// explicitly. (Go's filter has a `MaxRetension` time-based flush
// driven by `Tick` — the equivalent retention behavior is left as a
// follow-up; for the message-pump smoke test it's enough that the
// drain hook exists.)

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::fuzzer::filter::{Filter, FilterDecision};
use crate::fuzzer::AlgoMessage;

/// Builder for [`MessageReorderingFilter`]. Independent shuffle sizes
/// and seeds per direction; a size of `0` disables reordering on
/// that direction.
#[derive(Clone, Debug, Default)]
pub struct MessageReorderingFilterBuilder {
    outgoing_shuffle_size: usize,
    incoming_shuffle_size: usize,
    outgoing_seed: u64,
    incoming_seed: u64,
}

impl MessageReorderingFilterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure the outgoing shuffle pool. `size = 0` disables
    /// reordering. The RNG is seeded with `seed`.
    pub fn outgoing(mut self, size: usize, seed: u64) -> Self {
        self.outgoing_shuffle_size = size;
        self.outgoing_seed = seed;
        self
    }

    /// Configure the incoming shuffle pool. Same caveats as
    /// [`Self::outgoing`].
    pub fn incoming(mut self, size: usize, seed: u64) -> Self {
        self.incoming_shuffle_size = size;
        self.incoming_seed = seed;
        self
    }

    pub fn build(self) -> MessageReorderingFilter {
        MessageReorderingFilter {
            outgoing: ShufflePool::new(self.outgoing_shuffle_size, self.outgoing_seed),
            incoming: ShufflePool::new(self.incoming_shuffle_size, self.incoming_seed),
        }
    }
}

/// Per-direction shuffle pool — buffers up to `shuffle_size` messages
/// before emitting any; once full, every new arrival displaces a
/// random pool resident.
struct ShufflePool {
    shuffle_size: usize,
    rng: StdRng,
    pool: Vec<AlgoMessage>,
}

impl ShufflePool {
    fn new(shuffle_size: usize, seed: u64) -> Self {
        Self {
            shuffle_size,
            rng: StdRng::seed_from_u64(seed),
            pool: Vec::new(),
        }
    }

    /// Process one message arrival and return the harness's decision.
    fn handle(&mut self, msg: &AlgoMessage) -> FilterDecision {
        if self.shuffle_size == 0 {
            return FilterDecision::Keep;
        }

        // Append the new arrival to the pool.
        self.pool.push(msg.clone());

        if self.pool.len() <= self.shuffle_size {
            // Pool not yet over-full; hold this arrival.
            return FilterDecision::Drop;
        }

        // Pool is now over-full — pick a random resident to emit. The
        // chosen index spans `[0, pool.len())` so the just-pushed
        // message can win the lottery (no swap, identity passthrough)
        // or any older one (effective reorder). Mirrors Go's
        // `n.sendRnd.Intn(len(n.pendingSends))` at
        // `messageReorderingFilter_test.go:85`.
        let idx = self.rng.gen_range(0..self.pool.len());
        let displaced = self.pool.swap_remove(idx);
        FilterDecision::Substitute {
            with: vec![displaced],
        }
    }

    /// Drain any messages still parked in the pool (used by the
    /// scaffold's escape hatch to assert no message is lost).
    fn drain(&mut self) -> Vec<AlgoMessage> {
        std::mem::take(&mut self.pool)
    }

    /// Snapshot the current pool size — exposed for white-box
    /// assertions in unit tests.
    fn pool_size(&self) -> usize {
        self.pool.len()
    }
}

/// Per-node reorder filter. See module doc for semantics.
pub struct MessageReorderingFilter {
    outgoing: ShufflePool,
    incoming: ShufflePool,
}

impl Filter for MessageReorderingFilter {
    fn name(&self) -> &str {
        "MessageReorderingFilter"
    }

    fn filter_outgoing(&mut self, msg: &AlgoMessage) -> FilterDecision {
        self.outgoing.handle(msg)
    }

    fn filter_incoming(&mut self, msg: &AlgoMessage) -> FilterDecision {
        self.incoming.handle(msg)
    }
}

impl MessageReorderingFilter {
    /// Drain everything still parked in either direction. Returns
    /// `(outgoing_pool_remainder, incoming_pool_remainder)`. Used at
    /// end-of-test by harness consumers that need to assert
    /// no-message-loss invariants.
    pub fn drain_pending(&mut self) -> (Vec<AlgoMessage>, Vec<AlgoMessage>) {
        (self.outgoing.drain(), self.incoming.drain())
    }

    /// Snapshot the current outgoing pool size — exposed for unit
    /// tests that want to assert the "messages 1..N stay buffered until
    /// N+1" invariant.
    pub fn outgoing_pool_size(&self) -> usize {
        self.outgoing.pool_size()
    }

    /// Snapshot the current incoming pool size.
    pub fn incoming_pool_size(&self) -> usize {
        self.incoming.pool_size()
    }
}
