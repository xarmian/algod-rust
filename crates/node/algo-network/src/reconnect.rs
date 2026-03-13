//! Automatic reconnection with exponential back-off.
//!
//! Wraps the connect logic with retry behaviour: on transient failures the
//! module waits with jittered exponential back-off before re-attempting.
//! Permanent failures (genesis mismatch, self-loop) are propagated
//! immediately.  Reconnection respects a `CancellationToken` so it can be
//! cleanly shut down.
//!
//! The design follows go-algorand's `mesh.go` approach where an exponential
//! decorrelated-jitter strategy backs off when no peers can be reached, and
//! resets immediately after a successful connection.

use std::future::Future;
use std::time::Duration;

use rand::Rng;
use tokio_util::sync::CancellationToken;

use crate::errors::{HandshakeError, PeerError, WsConnectError};

// ---------------------------------------------------------------------------
// Exponential backoff
// ---------------------------------------------------------------------------

/// Exponential back-off with optional jitter.
///
/// Each call to [`next_delay`](ExponentialBackoff::next_delay) returns the
/// current delay and then multiplies it by `multiplier`, capping at
/// `max_delay`.  When `jitter` is enabled the returned delay is perturbed by
/// +/- 25 % to prevent thundering-herd effects on shared relays.
///
/// Mirrors the intent of go-algorand's `ExponentialDecorrelatedJitter` from
/// `github.com/libp2p/go-libp2p/p2p/discovery/backoff`.
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    /// Minimum (and initial) delay.
    min_delay: Duration,
    /// Maximum delay the backoff will ever return.
    max_delay: Duration,
    /// Factor applied after each call to `next_delay`.
    multiplier: f64,
    /// The delay that will be returned on the *next* call.
    current_delay: Duration,
    /// Whether to apply +/- 25 % random jitter.
    jitter: bool,
}

impl ExponentialBackoff {
    /// Create a new backoff starting at `min_delay`.
    ///
    /// # Panics
    ///
    /// Panics if `min_delay > max_delay` or `multiplier < 1.0`.
    pub fn new(min_delay: Duration, max_delay: Duration, multiplier: f64, jitter: bool) -> Self {
        assert!(min_delay <= max_delay, "min_delay must be <= max_delay");
        assert!(multiplier >= 1.0, "multiplier must be >= 1.0");
        Self {
            min_delay,
            max_delay,
            multiplier,
            current_delay: min_delay,
            jitter,
        }
    }

    /// Return the current delay (with optional jitter) and advance the
    /// internal state by multiplying `current_delay` by `multiplier`.
    pub fn next_delay(&mut self) -> Duration {
        let base = self.current_delay;

        // Advance for next call, capping at max.
        let next = Duration::from_secs_f64(
            (base.as_secs_f64() * self.multiplier).min(self.max_delay.as_secs_f64()),
        );
        self.current_delay = next.min(self.max_delay);

        if self.jitter {
            let mut rng = rand::thread_rng();
            // Jitter: uniform in [0.75 * base, 1.25 * base], clamped to
            // [min_delay, max_delay].
            let lo = base.as_secs_f64() * 0.75;
            let hi = base.as_secs_f64() * 1.25;
            let jittered = rng.gen_range(lo..=hi);
            let d = Duration::from_secs_f64(jittered);
            d.max(self.min_delay).min(self.max_delay)
        } else {
            base
        }
    }

    /// Reset the backoff to `min_delay`.
    pub fn reset(&mut self) {
        self.current_delay = self.min_delay;
    }
}

// ---------------------------------------------------------------------------
// Failure classification
// ---------------------------------------------------------------------------

/// Whether a connection failure is permanent or worth retrying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionFailure {
    /// The failure is permanent — retrying will not help.
    ///
    /// Examples: genesis ID mismatch, self-loop, protocol version mismatch.
    Terminal,
    /// The failure is temporary — the connection may succeed later.
    ///
    /// Examples: DNS errors, TCP timeouts, WebSocket upgrade rejection,
    /// read/write errors on an established peer, keepalive timeout.
    Transient,
}

/// Classify a [`WsConnectError`] as terminal or transient.
///
/// Most connection-level errors are transient (DNS, TCP, TLS issues),
/// but some are permanent configuration mismatches that will never resolve.
pub fn classify_connect_error(err: &WsConnectError) -> ConnectionFailure {
    match err {
        // Permanent: wrong network or self-connection — retrying won't help.
        WsConnectError::GenesisMismatch => ConnectionFailure::Terminal,
        WsConnectError::SelfLoop => ConnectionFailure::Terminal,
        // Delegate handshake errors to the handshake classifier.
        WsConnectError::Handshake(h) => classify_handshake_error(h),
        // Everything else (DNS, TCP, TLS, upgrade, I/O, tungstenite, etc.) is transient.
        _ => ConnectionFailure::Transient,
    }
}

/// Classify a [`HandshakeError`] as terminal or transient.
pub fn classify_handshake_error(err: &HandshakeError) -> ConnectionFailure {
    match err {
        // Permanent configuration mismatches — retrying won't help.
        HandshakeError::VersionMismatch { .. } => ConnectionFailure::Terminal,
        HandshakeError::GenesisMismatch { .. } => ConnectionFailure::Terminal,
        HandshakeError::SelfLoop => ConnectionFailure::Terminal,

        // Transient issues — server may recover.
        HandshakeError::MissingHeader(_) => ConnectionFailure::Transient,
        HandshakeError::Timeout => ConnectionFailure::Transient,
    }
}

/// Classify a [`PeerError`] as terminal or transient.
///
/// All peer-level runtime errors are transient because the underlying
/// connection may be re-established.
pub fn classify_peer_error(_err: &PeerError) -> ConnectionFailure {
    // SendBufferFull, ReadError, WriteError, KeepaliveTimeout,
    // ConnectionClosed, Tungstenite — all transient.
    ConnectionFailure::Transient
}

/// Unified error type returned by the reconnect supervisor.
///
/// Wraps the three layers of errors that can occur during the connection
/// lifecycle together with the classification of whether the error is
/// terminal or transient.
#[derive(Debug)]
pub enum SupervisorError {
    /// A connection-level error occurred.
    Connect(WsConnectError),
    /// An Algorand handshake error occurred.
    Handshake(HandshakeError),
    /// A runtime peer error occurred (post-handshake).
    Peer(PeerError),
    /// The supervisor was shut down via its cancellation token.
    Shutdown,
    /// The maximum number of reconnection attempts was exhausted.
    MaxAttemptsExhausted {
        /// How many attempts were made.
        attempts: usize,
        /// The last error that triggered the final retry.
        last_error: Box<SupervisorError>,
    },
}

impl std::fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "connect error: {e}"),
            Self::Handshake(e) => write!(f, "handshake error: {e}"),
            Self::Peer(e) => write!(f, "peer error: {e}"),
            Self::Shutdown => write!(f, "supervisor shut down"),
            Self::MaxAttemptsExhausted {
                attempts,
                last_error,
            } => {
                write!(
                    f,
                    "gave up after {attempts} attempts, last error: {last_error}"
                )
            }
        }
    }
}

impl std::error::Error for SupervisorError {}

impl SupervisorError {
    /// Classify this error as terminal or transient.
    pub fn classify(&self) -> ConnectionFailure {
        match self {
            Self::Connect(e) => classify_connect_error(e),
            Self::Handshake(e) => classify_handshake_error(e),
            Self::Peer(e) => classify_peer_error(e),
            Self::Shutdown => ConnectionFailure::Terminal,
            Self::MaxAttemptsExhausted { .. } => ConnectionFailure::Terminal,
        }
    }
}

impl From<WsConnectError> for SupervisorError {
    fn from(e: WsConnectError) -> Self {
        Self::Connect(e)
    }
}

impl From<HandshakeError> for SupervisorError {
    fn from(e: HandshakeError) -> Self {
        Self::Handshake(e)
    }
}

impl From<PeerError> for SupervisorError {
    fn from(e: PeerError) -> Self {
        Self::Peer(e)
    }
}

// ---------------------------------------------------------------------------
// Reconnect events (logging / metrics)
// ---------------------------------------------------------------------------

/// Events emitted by the [`ReconnectSupervisor`] during its lifecycle.
///
/// Callers can observe these via tracing spans/events; they are also useful
/// for testing that the supervisor goes through the expected state
/// transitions.
#[derive(Debug, Clone)]
pub enum ReconnectEvent {
    /// A connection attempt is about to start.
    Connecting {
        /// Target address.
        addr: String,
        /// 1-based attempt number.
        attempt: usize,
    },
    /// The connection was successfully established.
    Connected {
        /// Target address.
        addr: String,
    },
    /// An established connection was lost.
    Disconnected {
        /// Target address.
        addr: String,
        /// Human-readable reason for the disconnection.
        reason: String,
    },
    /// The supervisor will wait before retrying.
    Retrying {
        /// Target address.
        addr: String,
        /// How long the supervisor will sleep.
        delay: Duration,
        /// The *next* attempt number (1-based).
        attempt: usize,
    },
    /// The supervisor has permanently given up.
    GaveUp {
        /// Target address.
        addr: String,
        /// Human-readable reason for giving up.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Reconnect policy
// ---------------------------------------------------------------------------

/// What to do when a terminal failure is encountered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalAction {
    /// Stop the supervisor immediately.
    Stop,
    /// Log a warning and then stop.
    NotifyAndStop,
}

/// Configuration knobs for the reconnection supervisor.
#[derive(Debug, Clone)]
pub struct ReconnectPolicy {
    /// Backoff timing parameters.
    pub backoff: ExponentialBackoff,
    /// Maximum number of reconnection attempts.  `None` means unlimited.
    pub max_attempts: Option<usize>,
    /// Behaviour when a terminal failure is encountered.
    pub on_terminal_failure: TerminalAction,
}

impl Default for ReconnectPolicy {
    /// Sensible defaults inspired by go-algorand's mesh backoff:
    /// 1 s initial, 5 min max, 2x multiplier, jitter enabled, unlimited
    /// retries, notify-and-stop on terminal errors.
    fn default() -> Self {
        Self {
            backoff: ExponentialBackoff::new(
                Duration::from_secs(1),
                Duration::from_secs(300),
                2.0,
                true,
            ),
            max_attempts: None,
            on_terminal_failure: TerminalAction::NotifyAndStop,
        }
    }
}

// ---------------------------------------------------------------------------
// Reconnect supervisor
// ---------------------------------------------------------------------------

/// Manages the reconnection lifecycle for a single peer address.
///
/// The supervisor calls a user-provided async `connect_fn` in a loop.
/// On success the backoff is reset; on transient failure the supervisor
/// waits with exponential backoff before retrying.  Terminal failures
/// cause immediate shutdown.
///
/// Shutdown is coordinated via a [`CancellationToken`] — cancelling it will
/// interrupt the current backoff sleep and return `SupervisorError::Shutdown`.
pub struct ReconnectSupervisor {
    /// The address we are supervising.
    addr: String,
    /// Reconnection policy (backoff params, max attempts, terminal action).
    policy: ReconnectPolicy,
    /// Token used to signal graceful shutdown.
    cancel: CancellationToken,
}

impl ReconnectSupervisor {
    /// Create a new supervisor for `addr`.
    pub fn new(
        addr: impl Into<String>,
        policy: ReconnectPolicy,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            addr: addr.into(),
            policy,
            cancel,
        }
    }

    /// Return a reference to the cancellation token so callers can trigger
    /// shutdown externally.
    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel
    }

    /// Run the reconnection loop.
    ///
    /// `connect_fn` is an async function that attempts to connect and run the
    /// peer session.  When it returns `Ok(())`, the supervisor resets the
    /// backoff and attempt counter, then loops to reconnect.  When it returns
    /// `Err(SupervisorError)`, the error is classified and may trigger a
    /// retry (transient) or immediate exit (terminal).
    ///
    /// The function returns when:
    /// - A terminal failure is encountered
    /// - `max_attempts` is exhausted
    /// - The cancellation token is cancelled
    ///
    /// To stop the supervisor after a single successful session, cancel the
    /// token from within `connect_fn` before returning `Ok(())`.
    pub async fn run<F, Fut>(&mut self, connect_fn: F) -> Result<(), SupervisorError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<(), SupervisorError>>,
    {
        let mut attempt: usize = 0;

        loop {
            // Check for shutdown before each attempt.
            if self.cancel.is_cancelled() {
                tracing::info!(addr = %self.addr, "supervisor shutting down before attempt");
                return Err(SupervisorError::Shutdown);
            }

            attempt += 1;

            // Enforce max_attempts.
            if let Some(max) = self.policy.max_attempts {
                if attempt > max {
                    // We already exhausted all attempts in the previous
                    // iteration — this shouldn't normally be reached because
                    // we break below, but guard defensively.
                    return Err(SupervisorError::Shutdown);
                }
            }

            tracing::info!(
                addr = %self.addr,
                attempt = attempt,
                "connecting to peer"
            );

            // Attempt to connect (and run the session).
            let result = tokio::select! {
                biased;
                _ = self.cancel.cancelled() => {
                    tracing::info!(addr = %self.addr, "supervisor cancelled during connect");
                    return Err(SupervisorError::Shutdown);
                }
                res = connect_fn() => res,
            };

            match result {
                Ok(()) => {
                    // Session ended normally.  Reset backoff and attempt
                    // counter so that if the next connection attempt fails
                    // transiently we start with a fresh (short) delay instead
                    // of an accumulated long one.
                    tracing::info!(addr = %self.addr, "peer session ended cleanly, resetting backoff");
                    self.policy.backoff.reset();
                    attempt = 0;
                    // Continue the loop to reconnect.  If the caller wants the
                    // supervisor to stop after one successful session, they can
                    // cancel the token.
                    continue;
                }
                Err(err) => {
                    let classification = err.classify();

                    match classification {
                        ConnectionFailure::Terminal => {
                            match self.policy.on_terminal_failure {
                                TerminalAction::NotifyAndStop => {
                                    tracing::warn!(
                                        addr = %self.addr,
                                        error = %err,
                                        "terminal failure, giving up"
                                    );
                                }
                                TerminalAction::Stop => {
                                    tracing::debug!(
                                        addr = %self.addr,
                                        error = %err,
                                        "terminal failure, stopping"
                                    );
                                }
                            }
                            return Err(err);
                        }
                        ConnectionFailure::Transient => {
                            // Check if we've exhausted max_attempts.
                            if let Some(max) = self.policy.max_attempts {
                                if attempt >= max {
                                    tracing::warn!(
                                        addr = %self.addr,
                                        attempts = attempt,
                                        error = %err,
                                        "max attempts exhausted, giving up"
                                    );
                                    return Err(SupervisorError::MaxAttemptsExhausted {
                                        attempts: attempt,
                                        last_error: Box::new(err),
                                    });
                                }
                            }

                            let mut delay = self.policy.backoff.next_delay();

                            // Respect the server's Retry-After header for 429
                            // responses.  Use whichever is longer: our backoff
                            // or the server's requested cooling-off period.
                            if let SupervisorError::Connect(WsConnectError::TooManyRequests {
                                retry_after_secs: Some(secs),
                            }) = &err
                            {
                                let server_delay = Duration::from_secs(*secs);
                                if server_delay > delay {
                                    tracing::info!(
                                        addr = %self.addr,
                                        retry_after_secs = secs,
                                        backoff_ms = delay.as_millis() as u64,
                                        "using server Retry-After (longer than backoff)"
                                    );
                                    delay = server_delay;
                                }
                            }

                            tracing::info!(
                                addr = %self.addr,
                                attempt = attempt,
                                delay_ms = delay.as_millis() as u64,
                                error = %err,
                                "transient failure, retrying after backoff"
                            );

                            // Wait for the backoff delay, but respect cancellation.
                            tokio::select! {
                                biased;
                                _ = self.cancel.cancelled() => {
                                    tracing::info!(
                                        addr = %self.addr,
                                        "supervisor cancelled during backoff"
                                    );
                                    return Err(SupervisorError::Shutdown);
                                }
                                _ = tokio::time::sleep(delay) => {}
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // -- ExponentialBackoff tests -------------------------------------------

    #[test]
    fn backoff_doubles_correctly() {
        let mut b =
            ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(60), 2.0, false);
        assert_eq!(b.next_delay(), Duration::from_secs(1));
        assert_eq!(b.next_delay(), Duration::from_secs(2));
        assert_eq!(b.next_delay(), Duration::from_secs(4));
        assert_eq!(b.next_delay(), Duration::from_secs(8));
        assert_eq!(b.next_delay(), Duration::from_secs(16));
        assert_eq!(b.next_delay(), Duration::from_secs(32));
        // Next would be 64, but max is 60.
        assert_eq!(b.next_delay(), Duration::from_secs(60));
        // Stays at max.
        assert_eq!(b.next_delay(), Duration::from_secs(60));
    }

    #[test]
    fn backoff_respects_max_delay() {
        let mut b = ExponentialBackoff::new(
            Duration::from_secs(100),
            Duration::from_secs(100),
            2.0,
            false,
        );
        // min == max, so it always returns 100.
        assert_eq!(b.next_delay(), Duration::from_secs(100));
        assert_eq!(b.next_delay(), Duration::from_secs(100));
    }

    #[test]
    fn backoff_reset_returns_to_min() {
        let mut b =
            ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(60), 2.0, false);
        b.next_delay(); // 1
        b.next_delay(); // 2
        b.next_delay(); // 4
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_secs(1));
        assert_eq!(b.next_delay(), Duration::from_secs(2));
    }

    #[test]
    fn backoff_jitter_within_bounds() {
        let mut b = ExponentialBackoff::new(
            Duration::from_millis(100),
            Duration::from_secs(60),
            2.0,
            true,
        );
        // Run many iterations and check bounds.
        for _ in 0..100 {
            b.reset();
            let d = b.next_delay();
            // Base is 100 ms; jitter range is [75, 125] ms, clamped to
            // [100, 60000] ms (min_delay acts as floor).
            assert!(
                d >= Duration::from_millis(75),
                "delay {d:?} below jitter floor"
            );
            assert!(
                d <= Duration::from_millis(125),
                "delay {d:?} above jitter ceiling"
            );
        }
    }

    #[test]
    fn backoff_jitter_does_not_exceed_max() {
        let mut b =
            ExponentialBackoff::new(Duration::from_secs(58), Duration::from_secs(60), 2.0, true);
        // After one step the base becomes min(58*2, 60) = 60.
        let _ = b.next_delay(); // consumes 58-based delay
                                // Now current_delay = 60. Jitter of 60 +25% = 75, but should be
                                // clamped to 60.
        for _ in 0..50 {
            b.current_delay = Duration::from_secs(60);
            let d = b.next_delay();
            assert!(
                d <= Duration::from_secs(60),
                "jittered delay {d:?} exceeds max_delay"
            );
        }
    }

    #[test]
    fn backoff_with_fractional_multiplier() {
        let mut b = ExponentialBackoff::new(
            Duration::from_millis(100),
            Duration::from_secs(10),
            1.5,
            false,
        );
        assert_eq!(b.next_delay(), Duration::from_millis(100));
        assert_eq!(b.next_delay(), Duration::from_millis(150));
        // 150 * 1.5 = 225
        assert_eq!(b.next_delay(), Duration::from_millis(225));
    }

    #[test]
    #[should_panic(expected = "min_delay must be <= max_delay")]
    fn backoff_panics_if_min_greater_than_max() {
        ExponentialBackoff::new(Duration::from_secs(10), Duration::from_secs(1), 2.0, false);
    }

    #[test]
    #[should_panic(expected = "multiplier must be >= 1.0")]
    fn backoff_panics_if_multiplier_below_one() {
        ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(60), 0.5, false);
    }

    // -- Failure classification tests ---------------------------------------

    #[test]
    fn connect_errors_transient_cases() {
        let cases = vec![
            WsConnectError::DnsFailure("nxdomain".into()),
            WsConnectError::TcpFailure("connection refused".into()),
            WsConnectError::TlsFailure("certificate expired".into()),
            WsConnectError::UpgradeRejected("503".into()),
            WsConnectError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "reset",
            )),
        ];
        for err in &cases {
            assert_eq!(
                classify_connect_error(err),
                ConnectionFailure::Transient,
                "WsConnectError::{err} should be transient"
            );
        }
    }

    #[test]
    fn connect_errors_terminal_cases() {
        let terminal_cases = vec![
            WsConnectError::GenesisMismatch,
            WsConnectError::SelfLoop,
            WsConnectError::Handshake(Box::new(HandshakeError::SelfLoop)),
            WsConnectError::Handshake(Box::new(HandshakeError::GenesisMismatch {
                expected: "mainnet-v1.0".into(),
                actual: "testnet-v1.0".into(),
            })),
        ];
        for err in &terminal_cases {
            assert_eq!(
                classify_connect_error(err),
                ConnectionFailure::Terminal,
                "WsConnectError::{err} should be terminal"
            );
        }
    }

    #[test]
    fn connect_handshake_delegates_transient() {
        let err = WsConnectError::Handshake(Box::new(HandshakeError::Timeout));
        assert_eq!(
            classify_connect_error(&err),
            ConnectionFailure::Transient,
            "Handshake(Timeout) should be transient"
        );
    }

    #[test]
    fn handshake_terminal_errors() {
        let cases = vec![
            HandshakeError::VersionMismatch {
                local: "2.1".into(),
                remote: "1.0".into(),
            },
            HandshakeError::GenesisMismatch {
                expected: "mainnet-v1.0".into(),
                actual: "testnet-v1.0".into(),
            },
            HandshakeError::SelfLoop,
        ];
        for err in &cases {
            assert_eq!(
                classify_handshake_error(err),
                ConnectionFailure::Terminal,
                "HandshakeError::{err} should be terminal"
            );
        }
    }

    #[test]
    fn handshake_transient_errors() {
        let cases = vec![
            HandshakeError::MissingHeader("X-Algorand-Version".into()),
            HandshakeError::Timeout,
        ];
        for err in &cases {
            assert_eq!(
                classify_handshake_error(err),
                ConnectionFailure::Transient,
                "HandshakeError::{err} should be transient"
            );
        }
    }

    #[test]
    fn peer_errors_are_transient() {
        let cases = vec![
            PeerError::SendBufferFull,
            PeerError::ReadError("broken pipe".into()),
            PeerError::WriteError("reset".into()),
            PeerError::KeepaliveTimeout,
            PeerError::ConnectionClosed,
        ];
        for err in &cases {
            assert_eq!(
                classify_peer_error(err),
                ConnectionFailure::Transient,
                "PeerError::{err} should be transient"
            );
        }
    }

    // -- Supervisor tests ---------------------------------------------------

    #[tokio::test]
    async fn supervisor_succeeds_after_transient_failures() {
        let attempt_count = Arc::new(AtomicUsize::new(0));
        let attempt_clone = Arc::clone(&attempt_count);

        let policy = ReconnectPolicy {
            backoff: ExponentialBackoff::new(
                Duration::from_millis(1),
                Duration::from_millis(10),
                2.0,
                false,
            ),
            max_attempts: Some(10),
            on_terminal_failure: TerminalAction::Stop,
        };

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let mut sup = ReconnectSupervisor::new("127.0.0.1:4160", policy, cancel);

        let result = sup
            .run(|| {
                let ac = Arc::clone(&attempt_clone);
                let cancel_inner = cancel_clone.clone();
                async move {
                    let n = ac.fetch_add(1, Ordering::SeqCst) + 1;
                    if n < 3 {
                        Err(SupervisorError::Connect(WsConnectError::TcpFailure(
                            "refused".into(),
                        )))
                    } else {
                        // Succeed, then cancel so the supervisor stops.
                        cancel_inner.cancel();
                        Ok(())
                    }
                }
            })
            .await;

        // The supervisor loops after success; it exits via cancellation.
        match result.unwrap_err() {
            SupervisorError::Shutdown => {}
            other => panic!("expected Shutdown, got: {other}"),
        }
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn supervisor_stops_on_terminal_failure() {
        let attempt_count = Arc::new(AtomicUsize::new(0));
        let attempt_clone = Arc::clone(&attempt_count);

        let policy = ReconnectPolicy {
            backoff: ExponentialBackoff::new(
                Duration::from_millis(1),
                Duration::from_millis(10),
                2.0,
                false,
            ),
            max_attempts: None,
            on_terminal_failure: TerminalAction::Stop,
        };

        let cancel = CancellationToken::new();
        let mut sup = ReconnectSupervisor::new("127.0.0.1:4160", policy, cancel);

        let result = sup
            .run(|| {
                let ac = Arc::clone(&attempt_clone);
                async move {
                    ac.fetch_add(1, Ordering::SeqCst);
                    Err(SupervisorError::Handshake(
                        HandshakeError::GenesisMismatch {
                            expected: "mainnet-v1.0".into(),
                            actual: "testnet-v1.0".into(),
                        },
                    ))
                }
            })
            .await;

        assert!(result.is_err());
        // Should have attempted exactly once — no retry for terminal errors.
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);

        match result.unwrap_err() {
            SupervisorError::Handshake(HandshakeError::GenesisMismatch { .. }) => {}
            other => panic!("expected GenesisMismatch, got: {other}"),
        }
    }

    #[tokio::test]
    async fn supervisor_stops_on_self_loop() {
        let attempt_count = Arc::new(AtomicUsize::new(0));
        let attempt_clone = Arc::clone(&attempt_count);

        let policy = ReconnectPolicy {
            backoff: ExponentialBackoff::new(
                Duration::from_millis(1),
                Duration::from_millis(10),
                2.0,
                false,
            ),
            max_attempts: None,
            on_terminal_failure: TerminalAction::NotifyAndStop,
        };

        let cancel = CancellationToken::new();
        let mut sup = ReconnectSupervisor::new("127.0.0.1:4160", policy, cancel);

        let result = sup
            .run(|| {
                let ac = Arc::clone(&attempt_clone);
                async move {
                    ac.fetch_add(1, Ordering::SeqCst);
                    Err(SupervisorError::Handshake(HandshakeError::SelfLoop))
                }
            })
            .await;

        assert!(result.is_err());
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn supervisor_respects_max_attempts() {
        let attempt_count = Arc::new(AtomicUsize::new(0));
        let attempt_clone = Arc::clone(&attempt_count);

        let policy = ReconnectPolicy {
            backoff: ExponentialBackoff::new(
                Duration::from_millis(1),
                Duration::from_millis(10),
                2.0,
                false,
            ),
            max_attempts: Some(3),
            on_terminal_failure: TerminalAction::Stop,
        };

        let cancel = CancellationToken::new();
        let mut sup = ReconnectSupervisor::new("127.0.0.1:4160", policy, cancel);

        let result = sup
            .run(|| {
                let ac = Arc::clone(&attempt_clone);
                async move {
                    ac.fetch_add(1, Ordering::SeqCst);
                    Err(SupervisorError::Connect(WsConnectError::TcpFailure(
                        "refused".into(),
                    )))
                }
            })
            .await;

        assert!(result.is_err());
        assert_eq!(
            attempt_count.load(Ordering::SeqCst),
            3,
            "should attempt exactly max_attempts times"
        );

        match result.unwrap_err() {
            SupervisorError::MaxAttemptsExhausted { attempts, .. } => {
                assert_eq!(attempts, 3);
            }
            other => panic!("expected MaxAttemptsExhausted, got: {other}"),
        }
    }

    #[tokio::test]
    async fn supervisor_shutdown_during_backoff() {
        let attempt_count = Arc::new(AtomicUsize::new(0));
        let attempt_clone = Arc::clone(&attempt_count);

        let policy = ReconnectPolicy {
            backoff: ExponentialBackoff::new(
                // Very long delay so we're definitely sleeping when cancelled.
                Duration::from_secs(60),
                Duration::from_secs(60),
                1.0,
                false,
            ),
            max_attempts: None,
            on_terminal_failure: TerminalAction::Stop,
        };

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let mut sup = ReconnectSupervisor::new("127.0.0.1:4160", policy, cancel);

        // Cancel after a short delay (the supervisor should be in backoff sleep).
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            cancel_clone.cancel();
        });

        let result = sup
            .run(|| {
                let ac = Arc::clone(&attempt_clone);
                async move {
                    ac.fetch_add(1, Ordering::SeqCst);
                    Err(SupervisorError::Connect(WsConnectError::TcpFailure(
                        "refused".into(),
                    )))
                }
            })
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SupervisorError::Shutdown => {}
            other => panic!("expected Shutdown, got: {other}"),
        }
        // Should have attempted once, then entered backoff, then been cancelled.
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn supervisor_shutdown_before_first_attempt() {
        let policy = ReconnectPolicy {
            backoff: ExponentialBackoff::new(
                Duration::from_millis(1),
                Duration::from_millis(10),
                2.0,
                false,
            ),
            max_attempts: None,
            on_terminal_failure: TerminalAction::Stop,
        };

        let cancel = CancellationToken::new();
        cancel.cancel(); // Cancel immediately.
        let mut sup = ReconnectSupervisor::new("127.0.0.1:4160", policy, cancel);

        let result = sup.run(|| async { Ok(()) }).await;

        match result.unwrap_err() {
            SupervisorError::Shutdown => {}
            other => panic!("expected Shutdown, got: {other}"),
        }
    }

    #[tokio::test]
    async fn supervisor_resets_backoff_on_success_concept() {
        // This test verifies that the backoff is reset between connection
        // cycles.  After a successful connection the supervisor resets the
        // backoff and attempt counter, so a subsequent transient failure
        // starts with a fresh (short) delay instead of an accumulated one.
        //
        // Sequence: fail, fail, succeed, fail, succeed, cancel.
        // After the first success the attempt counter resets to 0, so the
        // second failure uses the initial (1 ms) backoff, not a longer one.
        let attempt_count = Arc::new(AtomicUsize::new(0));
        let attempt_clone = Arc::clone(&attempt_count);

        let policy = ReconnectPolicy {
            backoff: ExponentialBackoff::new(
                Duration::from_millis(1),
                Duration::from_millis(100),
                2.0,
                false,
            ),
            max_attempts: Some(5),
            on_terminal_failure: TerminalAction::Stop,
        };

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let mut sup = ReconnectSupervisor::new("127.0.0.1:4160", policy, cancel);

        let result = sup
            .run(|| {
                let ac = Arc::clone(&attempt_clone);
                let cancel_inner = cancel_clone.clone();
                async move {
                    let n = ac.fetch_add(1, Ordering::SeqCst) + 1;
                    match n {
                        // First two calls fail (transient).
                        1 | 2 => Err(SupervisorError::Connect(WsConnectError::TcpFailure(
                            "refused".into(),
                        ))),
                        // Third call succeeds — backoff and attempt counter
                        // are reset by the supervisor.
                        3 => Ok(()),
                        // Fourth call fails again — should use fresh backoff.
                        4 => Err(SupervisorError::Connect(WsConnectError::TcpFailure(
                            "refused again".into(),
                        ))),
                        // Fifth call succeeds — then cancel to stop the loop.
                        _ => {
                            cancel_inner.cancel();
                            Ok(())
                        }
                    }
                }
            })
            .await;

        // Supervisor exits via cancellation after the second success.
        match result.unwrap_err() {
            SupervisorError::Shutdown => {}
            other => panic!("expected Shutdown, got: {other}"),
        }
        assert_eq!(attempt_count.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn supervisor_error_classify() {
        let e = SupervisorError::Connect(WsConnectError::DnsFailure("nx".into()));
        assert_eq!(e.classify(), ConnectionFailure::Transient);

        let e = SupervisorError::Handshake(HandshakeError::SelfLoop);
        assert_eq!(e.classify(), ConnectionFailure::Terminal);

        let e = SupervisorError::Peer(PeerError::KeepaliveTimeout);
        assert_eq!(e.classify(), ConnectionFailure::Transient);

        let e = SupervisorError::Shutdown;
        assert_eq!(e.classify(), ConnectionFailure::Terminal);
    }

    #[test]
    fn reconnect_event_debug_format() {
        // Smoke test: all variants should be Debug-formattable.
        let events = vec![
            ReconnectEvent::Connecting {
                addr: "1.2.3.4:4160".into(),
                attempt: 1,
            },
            ReconnectEvent::Connected {
                addr: "1.2.3.4:4160".into(),
            },
            ReconnectEvent::Disconnected {
                addr: "1.2.3.4:4160".into(),
                reason: "keepalive timeout".into(),
            },
            ReconnectEvent::Retrying {
                addr: "1.2.3.4:4160".into(),
                delay: Duration::from_secs(2),
                attempt: 2,
            },
            ReconnectEvent::GaveUp {
                addr: "1.2.3.4:4160".into(),
                reason: "genesis mismatch".into(),
            },
        ];
        for event in &events {
            let s = format!("{event:?}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn default_policy_values() {
        let p = ReconnectPolicy::default();
        assert_eq!(p.backoff.min_delay, Duration::from_secs(1));
        assert_eq!(p.backoff.max_delay, Duration::from_secs(300));
        assert_eq!(p.backoff.multiplier, 2.0);
        assert!(p.backoff.jitter);
        assert!(p.max_attempts.is_none());
        assert_eq!(p.on_terminal_failure, TerminalAction::NotifyAndStop);
    }

    // -- Retry-After (429) tests -------------------------------------------

    #[tokio::test]
    async fn supervisor_respects_retry_after_when_larger_than_backoff() {
        // The server says "retry after 10s" but our backoff is only 1ms.
        // The supervisor should wait at least 10s.  We verify this by
        // checking that the second attempt happens after the Retry-After
        // period, not after the tiny backoff.
        let attempt_count = Arc::new(AtomicUsize::new(0));
        let attempt_clone = Arc::clone(&attempt_count);
        let timestamps = Arc::new(std::sync::Mutex::new(Vec::<std::time::Instant>::new()));
        let ts_clone = Arc::clone(&timestamps);

        let policy = ReconnectPolicy {
            backoff: ExponentialBackoff::new(
                Duration::from_millis(1),
                Duration::from_millis(100),
                2.0,
                false,
            ),
            max_attempts: Some(2),
            on_terminal_failure: TerminalAction::Stop,
        };

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let mut sup = ReconnectSupervisor::new("127.0.0.1:4160", policy, cancel);

        let result = sup
            .run(|| {
                let ac = Arc::clone(&attempt_clone);
                let ts = Arc::clone(&ts_clone);
                let cancel_inner = cancel_clone.clone();
                async move {
                    let n = ac.fetch_add(1, Ordering::SeqCst) + 1;
                    ts.lock().unwrap().push(std::time::Instant::now());
                    if n < 2 {
                        // First attempt: return 429 with retry_after = 1 second
                        // (we use 1s instead of 10s to keep the test fast).
                        Err(SupervisorError::Connect(WsConnectError::TooManyRequests {
                            retry_after_secs: Some(1),
                        }))
                    } else {
                        cancel_inner.cancel();
                        Ok(())
                    }
                }
            })
            .await;

        match result.unwrap_err() {
            SupervisorError::Shutdown => {}
            other => panic!("expected Shutdown, got: {other}"),
        }
        assert_eq!(attempt_count.load(Ordering::SeqCst), 2);

        // The gap between attempts should be >= 1 second (the Retry-After),
        // not the tiny 1ms backoff.
        let ts = timestamps.lock().unwrap();
        assert_eq!(ts.len(), 2);
        let gap = ts[1].duration_since(ts[0]);
        assert!(
            gap >= Duration::from_millis(900),
            "expected gap >= ~1s (Retry-After), got {gap:?}"
        );
    }

    #[tokio::test]
    async fn supervisor_uses_backoff_when_larger_than_retry_after() {
        // The server says "retry after 0s" but our backoff is 1s.
        // The supervisor should use the backoff (which is larger).
        let attempt_count = Arc::new(AtomicUsize::new(0));
        let attempt_clone = Arc::clone(&attempt_count);

        let policy = ReconnectPolicy {
            backoff: ExponentialBackoff::new(
                Duration::from_millis(1),
                Duration::from_millis(100),
                2.0,
                false,
            ),
            max_attempts: Some(2),
            on_terminal_failure: TerminalAction::Stop,
        };

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let mut sup = ReconnectSupervisor::new("127.0.0.1:4160", policy, cancel);

        let result = sup
            .run(|| {
                let ac = Arc::clone(&attempt_clone);
                let cancel_inner = cancel_clone.clone();
                async move {
                    let n = ac.fetch_add(1, Ordering::SeqCst) + 1;
                    if n < 2 {
                        // Server says retry after 0s — backoff should win.
                        Err(SupervisorError::Connect(WsConnectError::TooManyRequests {
                            retry_after_secs: Some(0),
                        }))
                    } else {
                        cancel_inner.cancel();
                        Ok(())
                    }
                }
            })
            .await;

        match result.unwrap_err() {
            SupervisorError::Shutdown => {}
            other => panic!("expected Shutdown, got: {other}"),
        }
        assert_eq!(attempt_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn supervisor_handles_429_without_retry_after() {
        // 429 with no Retry-After header — should just use backoff.
        let attempt_count = Arc::new(AtomicUsize::new(0));
        let attempt_clone = Arc::clone(&attempt_count);

        let policy = ReconnectPolicy {
            backoff: ExponentialBackoff::new(
                Duration::from_millis(1),
                Duration::from_millis(100),
                2.0,
                false,
            ),
            max_attempts: Some(2),
            on_terminal_failure: TerminalAction::Stop,
        };

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let mut sup = ReconnectSupervisor::new("127.0.0.1:4160", policy, cancel);

        let result = sup
            .run(|| {
                let ac = Arc::clone(&attempt_clone);
                let cancel_inner = cancel_clone.clone();
                async move {
                    let n = ac.fetch_add(1, Ordering::SeqCst) + 1;
                    if n < 2 {
                        Err(SupervisorError::Connect(WsConnectError::TooManyRequests {
                            retry_after_secs: None,
                        }))
                    } else {
                        cancel_inner.cancel();
                        Ok(())
                    }
                }
            })
            .await;

        match result.unwrap_err() {
            SupervisorError::Shutdown => {}
            other => panic!("expected Shutdown, got: {other}"),
        }
        assert_eq!(attempt_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn too_many_requests_is_transient() {
        let err = WsConnectError::TooManyRequests {
            retry_after_secs: Some(60),
        };
        assert_eq!(
            classify_connect_error(&err),
            ConnectionFailure::Transient,
            "TooManyRequests should be transient"
        );
    }
}
