// Clock abstraction for the agreement service.
//
// Mirrors go-algorand/util/timers/interface.go — `Clock[TimeoutType]`.
//
// The service uses a `Clock` to drive deadline-based timeouts. Production code
// uses `SystemClock` (wrapping `std::time::Instant`), which preserves the
// wall-clock semantics the service had before this abstraction existed.
// Tests and the simulation harness inject their own implementations — for
// example the `instant` clock in the simulate driver (see TASK-81) returns
// pre-closed receivers to drive deterministic, no-wall-time agreement rounds.
//
// Design notes vs Go:
//   - Go returns `<-chan time.Time`; we return `crossbeam_channel::Receiver<()>`
//     because the rest of the Rust demux already selects on crossbeam channels.
//     A sender going out of scope causes `recv()` to return `Err(Disconnected)`
//     — the crossbeam analogue of Go's "closed channel always receives zero".
//   - `decode` is intentionally NOT a trait method: making it one would require
//     a non-object-safe `Self` return, and we want `Arc<dyn Clock>` for the
//     Parameters field. Each Clock implementation provides its own associated
//     `decode` constructor (see `SystemClock::decode`).

use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::Receiver;

use crate::types::TimeoutType;

/// Abstraction over time sources used by the agreement service to drive
/// deadline-based timeouts.
///
/// Mirrors Go's `timers.Clock[TimeoutType]`
/// (`../go-algorand/util/timers/interface.go`).
///
/// Implementations must be cheap to clone via `Arc` because the service shares
/// one clock between the main loop and the demux loop.
pub trait Clock: Send + Sync {
    /// Returns a receiver that fires `delta` after this clock was zeroed.
    ///
    /// If `delta` has already elapsed, the returned receiver is pre-dropped —
    /// `Select::recv(&rx)` will report it as ready immediately and subsequent
    /// `recv()` calls will return `Err(Disconnected)`. This mirrors Go's
    /// "already-elapsed → closed channel" idiom.
    ///
    /// Repeated calls with the same `(delta, timeout_type)` MAY return the same
    /// receiver (the default production impl caches per `timeout_type`) to
    /// avoid spawning a new sleeper thread per demux iteration.
    ///
    /// Mirrors Go's `Clock.TimeoutAt`.
    fn timeout_at(&self, delta: Duration, timeout_type: TimeoutType) -> Receiver<()>;

    /// Returns the duration elapsed since this clock was zeroed.
    ///
    /// Mirrors Go's `Clock.Since`.
    fn since(&self) -> Duration;

    /// Returns a new `Clock` reset to "now". The returned clock has independent
    /// state; `self` is unchanged.
    ///
    /// Mirrors Go's `Clock.Zero`.
    fn zero(&self) -> Arc<dyn Clock>;

    /// Serialize this clock's state (typically just the zero timestamp) so that
    /// it can be persisted alongside agreement state for crash recovery.
    ///
    /// Mirrors Go's `Clock.Encode`. The inverse is each impl's associated
    /// `decode` constructor (see `SystemClock::decode`).
    fn encode(&self) -> Vec<u8>;
}
