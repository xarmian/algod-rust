// Clock abstraction for the agreement service.
//
// Mirrors go-algorand/util/timers/interface.go — `Clock[TimeoutType]`.
//
// The service uses a `Clock` to drive deadline-based timeouts. Production code
// uses `SystemClock` (wrapping `std::time::Instant` + `crossbeam_channel::after`),
// which preserves the wall-clock semantics the service had before this
// abstraction existed. Tests and the simulation harness inject their own
// implementations — for example the `instant` clock in the simulate driver
// (see TASK-81) returns pre-closed receivers to drive deterministic, no-wall-
// time agreement rounds.
//
// Design notes vs Go:
//   - Go returns `<-chan time.Time`; we return `crossbeam_channel::Receiver<Instant>`
//     because the rest of the Rust demux already selects on crossbeam channels,
//     and `crossbeam_channel::after(duration)` returns exactly this type.
//   - `zero` mutates in place (`&self`) via interior mutability rather than
//     returning a fresh `Arc<dyn Clock>` like Go does. Both `main_loop` and
//     `demux_loop` share one `Arc<dyn Clock>` — an in-place zero lets the
//     main loop rezero on `Action::Rezero` without having to swap Arcs across
//     thread boundaries.
//   - Serialization (`Encode`/`Decode` in Go) is deliberately omitted here;
//     the Rust agreement service persists clock zero via the existing
//     `ClockState` (see `persistence.rs`), not via the `Clock` trait. We'll
//     revisit if cadaver replay lands in a future task.

use std::time::{Duration, Instant};

use crossbeam_channel::Receiver;

use crate::types::TimeoutType;

/// Abstraction over time sources used by the agreement service to drive
/// deadline-based timeouts.
///
/// Mirrors Go's `timers.Clock[TimeoutType]`
/// (`../go-algorand/util/timers/interface.go`).
///
/// Implementations must be cheap to share via `Arc` because the service hands
/// the same clock to the main loop and the demux loop.
pub trait Clock: Send + Sync {
    /// Returns a receiver that fires `delta` after this clock was zeroed.
    ///
    /// If `delta` has already elapsed, the returned receiver is pre-dropped —
    /// `Select::recv(&rx)` will report it as ready immediately and subsequent
    /// `recv()` calls will return `Err(Disconnected)`. This mirrors Go's
    /// "already-elapsed → closed channel" idiom.
    ///
    /// The returned `Instant` is the firing time (matching
    /// `crossbeam_channel::after`); the demux discards it since only the
    /// readiness signal matters.
    ///
    /// Mirrors Go's `Clock.TimeoutAt`.
    fn timeout_at(&self, delta: Duration, timeout_type: TimeoutType) -> Receiver<Instant>;

    /// Returns the duration elapsed since this clock was zeroed.
    ///
    /// Mirrors Go's `Clock.Since`.
    fn since(&self) -> Duration;

    /// Resets this clock's zero to "now", in place.
    ///
    /// After this call, subsequent `timeout_at` calls measure delta from the
    /// new zero. Receivers produced by earlier calls are unaffected — they
    /// continue firing at their original scheduled time.
    ///
    /// Mirrors Go's `s.Clock = s.Clock.Zero()` reassignment; we mutate via
    /// interior mutability so both the main loop and demux loop observe the
    /// change through their shared `Arc<dyn Clock>` without an Arc swap.
    fn zero(&self);
}
