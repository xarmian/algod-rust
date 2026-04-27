// Deterministic mock clock for the agreement simulation driver.
//
// Mirrors go-algorand/agreement/agreementtest/simulate.go `instant` struct.
//
// The `InstantClock` is a `Clock` impl whose `timeout_at` and `zero` methods
// do NOT advance real time — instead they perform a synchronous handshake
// with an external driver (`run_round`) that steps the service through one
// agreement round per call. This is the piece that lets the simulate driver
// run N rounds deterministically without any real wall-clock waits.
//
// Handshake protocol:
//   - The service loop reaches the top of each round and calls `clock.zero()`.
//     `zero()` pushes to `z0` (bounded, capacity 1 — non-blocking) and then
//     pushes to `z1` (bounded, capacity 0 — blocks until the driver reads).
//   - The driver calls `run_round(r)`:
//       1. `z1_rx.recv()` — unblocks the service's `zero()`.
//       2. `timeout_at_rx.recv()` — blocks until the first-ever `timeout_at`
//          call drops its sender. After that first call, the channel stays
//          disconnected, so subsequent `run_round` calls return here
//          immediately. This mirrors Go's once-close semantics for
//          `timeoutAtCalled` (simulate.go:67).
//       3. `z0_rx.recv()` — drains the buffered `zero()` signal.
//   - After `zero()` returns in the service, the service proceeds to the
//     demux loop, which calls `clock.timeout_at(...)`. The first-ever call
//     drops the `timeout_at_sender` (releasing the driver's `run_round`
//     for round 1 above). Subsequent calls for `TimeoutType::Filter` with
//     no pseudonode backlog fire immediately — this is what lets the
//     service advance through vote steps without wall-clock waits.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossbeam_channel::{bounded, Receiver, Sender};

use algo_agreement::types::TimeoutType;
use algo_agreement::{Clock, EventsProcessingMonitor};
use algo_types::Round;

/// Mutable state for `InstantClock`. Kept small so the mutex is rarely
/// contested in practice.
struct InstantState {
    /// Per-queue backlog reported by the service's `EventsProcessingMonitor`.
    /// Read by `timeout_at` for `Deadline` requests: when the pseudonode
    /// queue is empty, the timeout fires immediately so the demux can
    /// advance the round through the filter step. Mirrors Go's
    /// `instant.HasPending("pseudonode")` check in
    /// `simulate.go::TimeoutAt` (simulate.go:71).
    events_queues: HashMap<String, usize>,
}

/// Deterministic clock used by the simulation harness.
///
/// The outer `Arc<InstantClock>` is shared between the test's driver thread
/// (which calls `run_round` / `shutdown`) and the agreement service threads
/// (which call the `Clock` trait methods). Passing a cloned `Arc` as
/// `Arc<dyn Clock>` to `Parameters::clock` gives both sides a handle to the
/// same underlying instance.
pub struct InstantClock {
    state: Mutex<InstantState>,

    /// Z0 — buffered capacity-1 channel that `zero()` writes to (non-blocking)
    /// and `run_round()` drains. Mirrors Go's `Z0 chan struct{}` in
    /// simulate.go:47.
    z0_tx: Sender<()>,
    z0_rx: Receiver<()>,

    /// Z1 — rendezvous (capacity 0) channel. `zero()` writes, blocking until
    /// `run_round()` (or `shutdown()`) reads. Mirrors Go's `Z1 chan struct{}`.
    z1_tx: Sender<()>,
    z1_rx: Receiver<()>,

    /// Held until the first-ever `timeout_at` call drops it. Dropping
    /// disconnects the channel and unblocks any current / future
    /// `run_round` call on `timeout_at_rx`. Mirrors the `close(timeoutAtCalled)`
    /// pattern in Go's `TimeoutAt` (simulate.go:67).
    timeout_at_sender: Mutex<Option<Sender<()>>>,
    timeout_at_rx: Receiver<()>,

    /// `true` once the first `timeout_at` has happened. Flipped via an atomic
    /// so the check is lock-free; only the first caller takes the mutex to
    /// drop the sender.
    first_timeout_seen: AtomicBool,

    /// Active outgoing-timeout senders, keyed by `TimeoutType`. Each entry
    /// corresponds to a receiver the service's `Demux::next` is currently
    /// (or was recently) selecting on. `shutdown()` drops all senders,
    /// disconnecting those receivers so the demux's `crossbeam::Select`
    /// fires and the service can observe the shutdown signal. Without this
    /// the demux would block forever (unlike SystemClock where the
    /// underlying `crossbeam::after` eventually fires on its own).
    active_senders: Mutex<HashMap<TimeoutType, Sender<Instant>>>,

    /// `true` once `shutdown()` has been called. `timeout_at` consults this
    /// flag to avoid a race where the demux requests a fresh timeout
    /// receiver AFTER shutdown has already cleared `active_senders` — the
    /// new sender would not be dropped, leaving the demux parked forever.
    /// When set, `timeout_at` returns a pre-disconnected receiver so every
    /// post-shutdown request surfaces as immediately ready.
    shutting_down: AtomicBool,
}

impl InstantClock {
    /// Construct a new `InstantClock` wrapped in `Arc`. Pass one clone to
    /// `Parameters::clock` (as `Arc<dyn Clock>`) and keep the other handle
    /// to drive `run_round` / `shutdown`.
    pub fn new() -> Arc<Self> {
        let (z0_tx, z0_rx) = bounded(1);
        let (z1_tx, z1_rx) = bounded(0);
        let (toa_tx, toa_rx) = bounded(0);
        Arc::new(Self {
            state: Mutex::new(InstantState {
                events_queues: HashMap::new(),
            }),
            z0_tx,
            z0_rx,
            z1_tx,
            z1_rx,
            timeout_at_sender: Mutex::new(Some(toa_tx)),
            timeout_at_rx: toa_rx,
            first_timeout_seen: AtomicBool::new(false),
            active_senders: Mutex::new(HashMap::new()),
            shutting_down: AtomicBool::new(false),
        })
    }

    /// Step the service through one agreement round. Call this from the
    /// driver thread after the service has been started and is about to
    /// begin round `r`.
    ///
    /// Mirrors Go's `instant.runRound(r)` in simulate.go:88.
    pub fn run_round(&self, _r: Round) {
        // Wait for the service's `zero()` to rendezvous via Z1.
        let _ = self.z1_rx.recv();
        // Wait for the first-ever `timeout_at` call (round 1 only); on
        // later rounds the channel is already disconnected and this returns
        // immediately — matching Go's once-close semantics.
        let _ = self.timeout_at_rx.recv();
        // Drain the buffered `zero()` signal on Z0.
        let _ = self.z0_rx.recv();
    }

    /// Called once by the driver after the last round, before the service
    /// is shut down. Drains any pending `zero()` AND drops all active
    /// timeout senders so the service's demux `Select` fires (its held
    /// receivers disconnect), letting the service observe the shutdown
    /// signal instead of blocking forever on never-firing channels.
    ///
    /// Mirrors Go's `instant.shutdown()` in simulate.go:94, plus the
    /// sender-drop dance needed because Rust's demux doesn't fall back to
    /// a real wall-clock `select_timeout` once `Clock` is injectable.
    pub fn shutdown(&self) {
        // Set the shutdown flag BEFORE clearing active senders so any
        // racing `timeout_at` call observes shutdown and returns a
        // pre-disconnected receiver rather than inserting a new sender
        // that would outlive the clear.
        self.shutting_down.store(true, Ordering::SeqCst);

        // Drop all active timeout senders. Any receiver the demux is
        // currently selecting on disconnects → `Select::select()` fires
        // that arm → `demux.next()` returns a Timeout event → the main
        // loop observes `quit` and breaks.
        self.active_senders
            .lock()
            .expect("InstantClock active_senders mutex poisoned")
            .clear();
        // Drain a pending `zero()` rendezvous, if any.
        let _ = self.z1_rx.try_recv();
    }

    /// `EventsProcessingMonitor` implementation is exposed via a separate
    /// wrapper (`InstantMonitor`) so that `Parameters::monitor` (generic
    /// `M`) and `Parameters::clock` (`Arc<dyn Clock>`) can both reference
    /// the same backing `InstantClock` through distinct types.
    pub fn make_monitor(self: &Arc<Self>) -> InstantMonitor {
        InstantMonitor {
            inner: Arc::clone(self),
        }
    }
}

impl Clock for InstantClock {
    fn timeout_at(&self, _delta: Duration, timeout_type: TimeoutType) -> Receiver<Instant> {
        // Atomic check-and-set for "has any timeout_at been called yet?"
        // The very first caller drops `timeout_at_sender`, which disconnects
        // the channel and releases `run_round`'s `timeout_at_rx.recv()` —
        // permanently. That matches Go's `close(timeoutAtCalled)` semantics.
        if !self.first_timeout_seen.swap(true, Ordering::SeqCst) {
            let mut sender = self
                .timeout_at_sender
                .lock()
                .expect("InstantClock timeout_at_sender mutex poisoned");
            *sender = None;
        }

        // If shutdown has been requested, any timeout request must surface
        // immediately so the demux's `Select` fires and the service can
        // observe `quit`. Returning a pre-disconnected receiver (sender
        // dropped) has the same effect as a closed Go channel.
        if self.shutting_down.load(Ordering::SeqCst) {
            let (tx, rx) = bounded::<Instant>(0);
            drop(tx);
            return rx;
        }

        // For `Deadline` requests (Rust demux's name for the round's
        // filter timer — set from `player.deadline.duration` which is
        // computed via `filter_timeout(period, params)`), fire
        // immediately when the pseudonode queue is drained. Mirrors
        // Go's `simulate.go:71-73` special-case for `TimeoutFilter`.
        // Without this, the filter-step transition (PROPOSE → SOFT)
        // never happens under the mock clock, and consensus stalls in
        // the propose step waiting for a never-firing timer.
        if timeout_type == TimeoutType::Deadline {
            let pseudo_pending = {
                let state = self
                    .state
                    .lock()
                    .expect("InstantClock state mutex poisoned");
                state.events_queues.get("pseudonode").copied().unwrap_or(0) > 0
            };
            if !pseudo_pending {
                // Empty pseudonode queue → fire the timer immediately
                // by returning a pre-disconnected receiver. The demux's
                // `Select` arm for this receiver fires with
                // `RecvError`, which the demux treats as a timeout
                // event — exactly what we want.
                let (tx, rx) = bounded::<Instant>(0);
                drop(tx);
                return rx;
            }
        }

        // FastRecovery (and Deadline-with-pending-pseudonode) timeouts
        // return a never-firing receiver. We keep the matched sender
        // alive on this clock so `shutdown()` can drop it later and
        // surface the receiver as Disconnected (waking the demux's
        // `Select`).
        let (tx, rx) = bounded::<Instant>(0);
        self.active_senders
            .lock()
            .expect("InstantClock active_senders mutex poisoned")
            .insert(timeout_type, tx);
        rx
    }

    fn since(&self) -> Duration {
        // Mock clock has no meaningful elapsed time; mirrors Go's
        // `instant.Since()` returning `0` in simulate.go:84.
        Duration::ZERO
    }

    fn zero(&self) {
        // Signal Z0 — bounded(1) buffer, so on the normal happy path this
        // slots in without blocking. If a previous round's signal is
        // still buffered (run_round hasn't drained it yet), `send` blocks
        // until it does — that preserves Go's semantics where `Z0 <-
        // struct{}{}` on a buffered-1 channel blocks on a full buffer.
        // Using `try_send` here silently dropped the marker and caused
        // run_round's `z0_rx.recv()` to deadlock on subsequent rounds
        // (Codex round-1 finding).
        let _ = self.z0_tx.send(());
        // Rendezvous on Z1 (cap 0) — blocks until `run_round` reads.
        // Mirrors Go's `instant.Zero()` in simulate.go:77-82.
        let _ = self.z1_tx.send(());
    }
}

/// Monitor-side view of an `InstantClock`. Hand this to `Parameters::monitor`
/// when constructing the service; it forwards queue updates to the same
/// backing `InstantClock` that `Parameters::clock` sees.
pub struct InstantMonitor {
    inner: Arc<InstantClock>,
}

impl EventsProcessingMonitor for InstantMonitor {
    fn update_events_queue(&self, queue_name: &str, queue_length: usize) {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("InstantClock state mutex poisoned");
        state
            .events_queues
            .insert(queue_name.to_string(), queue_length);
    }
}
