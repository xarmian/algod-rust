// Default production implementation of the `Clock` trait.
//
// Mirrors go-algorand/util/timers/monotonic.go — `Monotonic[TimeoutType]`.
//
// `SystemClock` wraps `std::time::Instant` and uses `thread::sleep` in a
// spawned thread to signal timeout receivers. Repeat calls for the same
// `TimeoutType` with matching `delta` return the cached receiver so the demux
// doesn't spawn a new sleeper thread on every iteration. This preserves the
// timing semantics the agreement service had before the `Clock` abstraction
// was introduced.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossbeam_channel::{bounded, Receiver};
use thiserror::Error;

use crate::clock::Clock;
use crate::types::TimeoutType;

/// Cached timeout entry so repeated `timeout_at(delta, ty)` calls with the
/// same `ty` and matching `delta` return the same receiver.
struct CachedTimeout {
    delta: Duration,
    rx: Receiver<()>,
}

/// Default production clock — wraps `Instant::now()` with a per-`TimeoutType`
/// cache, matching go-algorand's `timers.Monotonic`.
pub struct SystemClock {
    /// Monotonic zero point. Timeouts fire at `zero + delta`.
    zero: Instant,
    /// Wall-clock timestamp that corresponds to `zero`; used by `encode` so
    /// that persistence can be cross-checked against `SystemTime::now()` at
    /// restore time.
    zero_wall: SystemTime,
    /// Per-`TimeoutType` cache — mirrors `m.timeouts` in monotonic.go.
    timeouts: Mutex<HashMap<TimeoutType, CachedTimeout>>,
}

impl SystemClock {
    /// Create a new `SystemClock` zeroed at the current wall-clock instant,
    /// returning it as an `Arc<dyn Clock>` ready to hand to `Parameters`.
    ///
    /// Mirrors `timers.MakeMonotonicClock[TimeoutType](time.Now())` — the
    /// Go equivalent constructs and returns the concrete type; the Rust
    /// service threads clocks as trait objects so every call site wants the
    /// `Arc<dyn Clock>` shape.
    #[allow(clippy::new_ret_no_self)] // returns trait object by design — see doc.
    pub fn new() -> Arc<dyn Clock> {
        Arc::new(Self::with_zero(Instant::now(), SystemTime::now()))
    }

    /// Create a new `SystemClock` zeroed at the given instant and wall-clock
    /// stamp. Useful for tests that want a known reference point.
    pub fn with_zero(zero: Instant, zero_wall: SystemTime) -> Self {
        Self {
            zero,
            zero_wall,
            timeouts: Mutex::new(HashMap::new()),
        }
    }

    /// Reconstruct a `SystemClock` from the bytes produced by `encode`.
    ///
    /// The encoded payload is the clock's wall-clock zero timestamp expressed
    /// as nanoseconds since `UNIX_EPOCH`. The monotonic zero is reconstructed
    /// by projecting the wall-clock delta onto `Instant::now()`; if the stored
    /// zero is in the future (e.g. bogus payload, clock skew), we refuse to
    /// return a usable clock and surface `ClockDecodeError::ZeroInFuture`.
    pub fn decode(bytes: &[u8]) -> Result<Arc<dyn Clock>, ClockDecodeError> {
        if bytes.len() != 16 {
            return Err(ClockDecodeError::WrongLength {
                expected: 16,
                got: bytes.len(),
            });
        }
        let mut buf = [0u8; 16];
        buf.copy_from_slice(bytes);
        let nanos = u128::from_le_bytes(buf);
        let zero_wall = UNIX_EPOCH
            .checked_add(Duration::from_nanos(
                u64::try_from(nanos).map_err(|_| ClockDecodeError::Malformed)?,
            ))
            .ok_or(ClockDecodeError::Malformed)?;

        let now_wall = SystemTime::now();
        let elapsed_wall = now_wall
            .duration_since(zero_wall)
            .map_err(|_| ClockDecodeError::ZeroInFuture)?;
        let now_instant = Instant::now();
        let zero_instant = now_instant
            .checked_sub(elapsed_wall)
            .ok_or(ClockDecodeError::ZeroInFuture)?;

        Ok(Arc::new(Self::with_zero(zero_instant, zero_wall)))
    }
}

impl Clock for SystemClock {
    fn timeout_at(&self, delta: Duration, timeout_type: TimeoutType) -> Receiver<()> {
        let mut timeouts = self
            .timeouts
            .lock()
            .expect("SystemClock timeouts mutex poisoned");

        if let Some(cached) = timeouts.get(&timeout_type) {
            if cached.delta == delta {
                return cached.rx.clone();
            }
        }

        let target = self.zero + delta;
        let left = target.saturating_duration_since(Instant::now());
        let (tx, rx) = bounded::<()>(0);

        if left.is_zero() {
            // Already elapsed — drop tx so recv sees Disconnected immediately.
            drop(tx);
        } else {
            thread::Builder::new()
                .name(format!("clock-timeout-{timeout_type}"))
                .spawn(move || {
                    thread::sleep(left);
                    // Dropping tx here closes the channel, which the demux's
                    // crossbeam `Select::recv(&rx)` treats as a fired timeout.
                    drop(tx);
                })
                .expect("failed to spawn clock-timeout thread");
        }

        timeouts.insert(
            timeout_type,
            CachedTimeout {
                delta,
                rx: rx.clone(),
            },
        );
        rx
    }

    fn since(&self) -> Duration {
        Instant::now().saturating_duration_since(self.zero)
    }

    fn zero(&self) -> Arc<dyn Clock> {
        Arc::new(Self::with_zero(Instant::now(), SystemTime::now()))
    }

    fn encode(&self) -> Vec<u8> {
        // Serialize the wall-clock zero as u128 nanoseconds (little-endian).
        let nanos = self
            .zero_wall
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        nanos.to_le_bytes().to_vec()
    }
}

/// Errors returned by `SystemClock::decode`.
#[derive(Debug, Error)]
pub enum ClockDecodeError {
    /// Encoded payload had an unexpected length.
    #[error("clock decode: wrong length (expected {expected}, got {got})")]
    WrongLength { expected: usize, got: usize },
    /// Encoded payload did not represent a valid wall-clock timestamp.
    #[error("clock decode: malformed payload")]
    Malformed,
    /// The decoded zero timestamp is in the future relative to the current
    /// wall clock — cannot project onto a monotonic instant.
    #[error("clock decode: stored zero is in the future (clock skew or corrupt state)")]
    ZeroInFuture,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::select;

    #[test]
    fn since_is_small_at_construction() {
        let clock = SystemClock::new();
        let since = clock.since();
        // Allow a generous upper bound; we just want to assert it's not bogus.
        assert!(
            since < Duration::from_secs(1),
            "since() at construction was {:?}",
            since
        );
    }

    #[test]
    fn zero_resets_the_monotonic_reference() {
        let clock = SystemClock::new();
        thread::sleep(Duration::from_millis(20));
        let reset = clock.zero();
        // `reset.since()` should be much smaller than `clock.since()`.
        assert!(
            reset.since() < clock.since(),
            "zero() did not reset the monotonic reference (reset={:?}, clock={:?})",
            reset.since(),
            clock.since()
        );
    }

    #[test]
    fn timeout_at_elapsed_delta_fires_immediately() {
        let clock = SystemClock::new();
        // Sleep past the delta window.
        thread::sleep(Duration::from_millis(10));
        let rx = clock.timeout_at(Duration::from_millis(1), TimeoutType::Deadline);
        // With delta already elapsed, the receiver should be disconnected.
        assert!(
            rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "expected elapsed timeout_at to surface immediately"
        );
    }

    #[test]
    fn timeout_at_waits_before_firing() {
        let clock = SystemClock::new();
        let rx = clock.timeout_at(Duration::from_millis(50), TimeoutType::Deadline);
        // Before 50ms the receiver should not be ready.
        assert!(
            rx.recv_timeout(Duration::from_millis(10)).is_err(),
            "timeout_at fired before delta elapsed"
        );
        // After sufficient wait the timeout should fire (sender dropped).
        // We use select with a generous timeout to avoid flakiness under load.
        select! {
            recv(rx) -> res => {
                assert!(res.is_err(), "expected Disconnected once timer elapsed");
            },
            default(Duration::from_millis(500)) => {
                panic!("timeout_at did not fire within 500ms");
            }
        }
    }

    #[test]
    fn timeout_at_caches_per_timeout_type() {
        let clock = SystemClock::new();
        let rx_a = clock.timeout_at(Duration::from_secs(10), TimeoutType::Deadline);
        let rx_b = clock.timeout_at(Duration::from_secs(10), TimeoutType::Deadline);
        // Same delta + same type → same underlying receiver.
        assert!(rx_a.same_channel(&rx_b), "expected cached receiver reuse");
    }

    #[test]
    fn timeout_at_new_channel_when_delta_changes() {
        let clock = SystemClock::new();
        let rx_a = clock.timeout_at(Duration::from_secs(5), TimeoutType::Deadline);
        let rx_b = clock.timeout_at(Duration::from_secs(10), TimeoutType::Deadline);
        // Different delta → fresh receiver.
        assert!(
            !rx_a.same_channel(&rx_b),
            "expected new receiver when delta changed"
        );
    }

    #[test]
    fn encode_then_decode_roundtrip() {
        let clock = SystemClock::new();
        let encoded = clock.encode();
        assert_eq!(encoded.len(), 16, "encoded clock should be 16 bytes");
        let decoded = match SystemClock::decode(&encoded) {
            Ok(c) => c,
            Err(e) => panic!("decode should succeed: {e}"),
        };
        // since() on the decoded clock should be close to the original's since(),
        // with some tolerance for the decode-time gap.
        let orig_since = clock.since();
        let dec_since = decoded.since();
        let diff = if dec_since > orig_since {
            dec_since - orig_since
        } else {
            orig_since - dec_since
        };
        assert!(
            diff < Duration::from_millis(50),
            "decoded since drifted too far (orig={:?}, dec={:?}, diff={:?})",
            orig_since,
            dec_since,
            diff
        );
    }

    #[test]
    fn decode_rejects_wrong_length() {
        match SystemClock::decode(&[0u8; 8]) {
            Ok(_) => panic!("decode should reject short payloads"),
            Err(e) => assert!(matches!(e, ClockDecodeError::WrongLength { .. })),
        }
    }
}
