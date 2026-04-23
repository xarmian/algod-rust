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

/// Internal queue-name used by the agreement service when reporting
/// pseudonode backlog. Must match `crate::demux::EVENT_QUEUE_PSEUDONODE`
/// (`"pseudonode"`) — `timeout_at` inspects it to decide whether to fire
/// a Filter timeout immediately.
const PSEUDONODE_QUEUE: &str = "pseudonode";

/// Mutable state for `InstantClock`. Kept small so the mutex is rarely
/// contested in practice.
struct InstantState {
    /// Per-queue backlog reported by the service's `EventsProcessingMonitor`.
    /// `timeout_at` checks `pseudonode` to decide whether a Filter timeout
    /// should fire immediately (Go semantics: only when the pseudonode queue
    /// is empty, i.e. nothing locally pending).
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

    fn has_pending_pseudonode(&self) -> bool {
        let state = self
            .state
            .lock()
            .expect("InstantClock state mutex poisoned");
        state
            .events_queues
            .get(PSEUDONODE_QUEUE)
            .copied()
            .unwrap_or(0)
            > 0
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

        // Filter-step timeouts fire immediately when no pseudonode backlog
        // is present (Go semantics in simulate.go:71-73), letting the
        // service advance through vote steps without wall-clock waits.
        if timeout_type == TimeoutType::Filter && !self.has_pending_pseudonode() {
            let (tx, rx) = bounded::<Instant>(0);
            drop(tx);
            return rx;
        }

        // All other timeouts return a "never-fire" receiver — but we keep
        // the matched sender alive on this clock so `shutdown()` can drop
        // it later and surface the receiver as Disconnected (waking the
        // demux's `Select`). Without this the demux would block forever
        // once `run_round` returns — real wall-clock timeout can't save
        // us now that Clock is injectable.
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
        // Signal Z0 (non-blocking write into cap-1 buffer), then rendezvous
        // on Z1 which blocks until `run_round` reads. Mirrors Go's
        // `instant.Zero()` in simulate.go:77-82.
        let _ = self.z0_tx.try_send(());
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
