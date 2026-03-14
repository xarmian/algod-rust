//! Rejecting limit listener — semaphore-based TCP connection limiter.
//!
//! Wraps a [`tokio::net::TcpListener`] with a [`tokio::sync::Semaphore`] that
//! enforces a maximum number of simultaneous connections.  When the limit is
//! reached, new connections are accepted at the TCP level and then immediately
//! closed (the *rejecting* pattern), rather than leaving the client waiting in
//! a backlog.
//!
//! Reserved slots are kept for health-check connections so the node's
//! `/health` endpoint remains reachable even when the listener is at capacity.
//!
//! # Go reference
//!
//! `go-algorand/network/limitlistener/rejectingLimitListener.go`

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, TryAcquireError};
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Additional connection slots reserved for the health-check endpoint.
///
/// Matches Go's `ReservedHealthServiceConnections = 10` in
/// `network/wsNetwork.go`.
pub const RESERVED_HEALTH_SERVICE_CONNECTIONS: u32 = 10;

// ---------------------------------------------------------------------------
// ConnectionGuard
// ---------------------------------------------------------------------------

/// RAII guard that releases a semaphore permit when dropped, freeing a
/// connection slot in the [`RejectingLimitListener`].
///
/// Callers must hold this guard for the lifetime of the accepted connection.
#[derive(Debug)]
pub struct ConnectionGuard {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

// ---------------------------------------------------------------------------
// RejectingLimitListener
// ---------------------------------------------------------------------------

/// A TCP listener that enforces a concurrent-connection limit.
///
/// When the number of active connections (tracked via held [`ConnectionGuard`]s)
/// reaches the configured limit, the listener still calls `accept()` at the OS
/// level but immediately closes the resulting socket.  This ensures that
/// clients receive a clean TCP RST / close rather than timing out in the
/// kernel backlog.
///
/// The total capacity is `incoming_connections_limit + RESERVED_HEALTH_SERVICE_CONNECTIONS`.
#[derive(Debug)]
pub struct RejectingLimitListener {
    inner: TcpListener,
    semaphore: Arc<Semaphore>,
}

impl RejectingLimitListener {
    /// Create a new rejecting limit listener wrapping `listener`.
    ///
    /// `incoming_connections_limit` is the *application-level* limit (e.g. 2400).
    /// An additional [`RESERVED_HEALTH_SERVICE_CONNECTIONS`] slots are added on
    /// top for health-check traffic.
    pub fn new(listener: TcpListener, incoming_connections_limit: u32) -> Self {
        let total =
            incoming_connections_limit as usize + RESERVED_HEALTH_SERVICE_CONNECTIONS as usize;
        Self {
            inner: listener,
            semaphore: Arc::new(Semaphore::new(total)),
        }
    }

    /// Accept a new connection, enforcing the concurrency limit.
    ///
    /// On success returns the accepted [`TcpStream`], its remote
    /// [`SocketAddr`], and a [`ConnectionGuard`] that the caller **must** hold
    /// for the lifetime of the connection.  Dropping the guard releases the
    /// slot back to the semaphore.
    ///
    /// If the semaphore is exhausted the method still calls the underlying
    /// `accept()` so the OS backlog is drained, but immediately closes the
    /// socket and loops back to try again.
    ///
    /// Returns `Err` only if the underlying TCP accept fails (e.g. the
    /// listener has been closed).
    pub async fn accept(&self) -> std::io::Result<(TcpStream, SocketAddr, ConnectionGuard)> {
        loop {
            // Accept at the OS level first so we drain the backlog even when
            // the semaphore is full (matching Go's behaviour).
            let (stream, addr) = self.inner.accept().await?;

            // Try to acquire a permit *without* blocking.  If the semaphore is
            // exhausted we close the connection immediately.
            match self.semaphore.clone().try_acquire_owned() {
                Ok(permit) => {
                    debug!(%addr, "accepted connection");
                    return Ok((stream, addr, ConnectionGuard { _permit: permit }));
                }
                Err(TryAcquireError::NoPermits) => {
                    // Drop `stream` — this closes the TCP socket.
                    warn!(%addr, "connection limit reached, rejecting");
                    drop(stream);
                    // Loop back and accept the next one.
                }
                Err(TryAcquireError::Closed) => {
                    // Semaphore was closed — treat as listener shutdown.
                    return Err(std::io::Error::other("listener semaphore closed"));
                }
            }
        }
    }

    /// Returns the local address this listener is bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Returns a reference to the underlying [`TcpListener`].
    pub fn inner(&self) -> &TcpListener {
        &self.inner
    }

    /// Returns the number of currently available connection slots.
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    /// Helper: bind a listener on a random OS-assigned port on localhost.
    async fn bind_listener() -> TcpListener {
        TcpListener::bind("127.0.0.1:0").await.unwrap()
    }

    #[tokio::test]
    async fn accept_within_limit() {
        let inner = bind_listener().await;
        let addr = inner.local_addr().unwrap();
        // Limit of 2 (+ 10 reserved = 12 total permits).
        let listener = RejectingLimitListener::new(inner, 2);
        let total_permits = 2 + RESERVED_HEALTH_SERVICE_CONNECTIONS as usize;
        assert_eq!(listener.available_permits(), total_permits);

        // Connect one client.
        let _client1 = TcpStream::connect(addr).await.unwrap();
        let (_, _, guard1) = listener.accept().await.unwrap();
        assert_eq!(listener.available_permits(), total_permits - 1);

        // Connect a second client.
        let _client2 = TcpStream::connect(addr).await.unwrap();
        let (_, _, guard2) = listener.accept().await.unwrap();
        assert_eq!(listener.available_permits(), total_permits - 2);

        // Drop the first guard — slot should be released.
        drop(guard1);
        assert_eq!(listener.available_permits(), total_permits - 1);

        // Drop the second guard — all slots free.
        drop(guard2);
        assert_eq!(listener.available_permits(), total_permits);
    }

    #[tokio::test]
    async fn reject_over_limit() {
        // Use exactly 1 semaphore permit so we can easily test rejection.
        let listener = RejectingLimitListener {
            inner: bind_listener().await,
            semaphore: Arc::new(Semaphore::new(1)),
        };
        let addr = listener.local_addr().unwrap();

        // First connection should be accepted.
        let _client1 = TcpStream::connect(addr).await.unwrap();
        let (_stream1, _, guard1) = listener.accept().await.unwrap();
        assert_eq!(listener.available_permits(), 0);

        // Second connection should be rejected (accepted then immediately
        // closed). We need to connect and then check that the listener
        // eventually accepts a third connection after we free a slot.
        //
        // Strategy: spawn a task that connects a "rejected" client, then
        // another that frees the slot, and verify the third client succeeds.
        let addr2 = addr;
        let rejected_handle = tokio::spawn(async move {
            // This connection will be accepted at OS level but rejected by
            // the listener (closed immediately).
            let mut client = TcpStream::connect(addr2).await.unwrap();
            // Try to write — if the server closed us, we'll get an error
            // (eventually, after the RST propagates).
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            // The write may or may not fail depending on timing, but the
            // important thing is the connection was closed server-side.
            let _ = client.write_all(b"hello").await;
        });

        // Spawn an accept loop in the background. The second accept will
        // reject the connection and loop; then when we drop guard1 and a
        // third client connects, it should succeed.
        let listener = Arc::new(listener);
        let listener2 = listener.clone();

        let accept_handle = tokio::spawn(async move {
            // This will first reject the "rejected" client's connection,
            // then accept the next valid one.
            listener2.accept().await.unwrap()
        });

        // Give the accept loop a moment to drain the rejected connection.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // Free the slot held by the first connection.
        drop(guard1);

        // Now connect a third client — this one should be accepted.
        let _client3 = TcpStream::connect(addr).await.unwrap();

        let (_stream3, _, _guard3) =
            tokio::time::timeout(std::time::Duration::from_secs(2), accept_handle)
                .await
                .expect("accept should complete within timeout")
                .expect("accept task should not panic");

        let _ = rejected_handle.await;
    }

    #[tokio::test]
    async fn guard_drop_releases_slot() {
        let inner = bind_listener().await;
        let addr = inner.local_addr().unwrap();
        let listener = RejectingLimitListener {
            inner,
            semaphore: Arc::new(Semaphore::new(3)),
        };

        let initial = listener.available_permits();
        assert_eq!(initial, 3);

        // Accept three connections.
        let mut guards = Vec::new();
        for _ in 0..3 {
            let _client = TcpStream::connect(addr).await.unwrap();
            let (_, _, guard) = listener.accept().await.unwrap();
            guards.push(guard);
        }
        assert_eq!(listener.available_permits(), 0);

        // Drop guards one at a time and verify permits are reclaimed.
        guards.pop();
        assert_eq!(listener.available_permits(), 1);
        guards.pop();
        assert_eq!(listener.available_permits(), 2);
        guards.pop();
        assert_eq!(listener.available_permits(), 3);
    }

    #[tokio::test]
    async fn local_addr_matches_inner() {
        let inner = bind_listener().await;
        let expected = inner.local_addr().unwrap();
        let listener = RejectingLimitListener::new(inner, 100);
        assert_eq!(listener.local_addr().unwrap(), expected);
    }
}
