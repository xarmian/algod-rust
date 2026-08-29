// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-IP connection tracking and rate limiting.
//!
//! Mirrors the connection-counting and rate-limiting logic from
//! go-algorand `network/requestTracker.go` (lines 243-296). The Go
//! implementation uses a sliding window: it records a timestamp for each
//! accepted connection and counts how many connections from a given IP
//! occurred within the last `ConnectionsRateLimitingWindowSeconds`.
//!
//! This module provides a simplified, reusable [`ConnectionTracker`] that
//! can be embedded into the network listener to enforce per-IP limits.
//!
//! ## Design
//!
//! - **Connection counting**: an atomic count per IP, incremented on
//!   `track_connection` and decremented on `release_connection`.
//! - **Rate limiting**: a sliding-window approach (matching Go) that
//!   records timestamps of connection attempts and counts those within
//!   a configurable window.
//! - **Thread safety**: all mutable state is behind a single
//!   [`std::sync::Mutex`], consistent with the rest of the crate.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// ConnectionTracker
// ---------------------------------------------------------------------------

/// Per-IP connection tracker with rate limiting.
///
/// Tracks two independent dimensions per IP address:
///
/// 1. **Active connection count** --- incremented by [`track_connection`] and
///    decremented by [`release_connection`]. Checked via
///    [`check_connection_limit`].
///
/// 2. **Connection attempt rate** --- a sliding-window counter that records
///    the [`Instant`] of each connection attempt. Checked via
///    [`check_rate_limit`], which counts attempts within the configured
///    window and compares against a per-second threshold.
///
/// The naming intentionally avoids `RequestTracker` to prevent confusion
/// with the request/response correlation tracker in [`crate::request_response`].
///
/// [`track_connection`]: ConnectionTracker::track_connection
/// [`release_connection`]: ConnectionTracker::release_connection
/// [`check_connection_limit`]: ConnectionTracker::check_connection_limit
/// [`check_rate_limit`]: ConnectionTracker::check_rate_limit
pub struct ConnectionTracker {
    inner: Mutex<TrackerInner>,
}

struct TrackerInner {
    /// Active (open) connection count per IP.
    active_connections: HashMap<IpAddr, u32>,

    /// Sliding-window timestamps of connection attempts per IP.
    /// Each entry is a sorted (by construction) list of [`Instant`] values.
    connection_attempts: HashMap<IpAddr, Vec<Instant>>,

    /// Duration of the sliding rate-limit window.
    /// Attempts older than `now - window` are pruned.
    rate_limit_window: Duration,
}

impl ConnectionTracker {
    /// Create a new `ConnectionTracker` with the given rate-limit window.
    ///
    /// The `window` controls how far back in time connection attempts are
    /// counted when checking the rate limit. A typical value is 1 second
    /// (matching Go's `ConnectionsRateLimitingWindowSeconds`). Pass
    /// [`Duration::ZERO`] to effectively disable rate limiting.
    pub fn new(window: Duration) -> Self {
        Self {
            inner: Mutex::new(TrackerInner {
                active_connections: HashMap::new(),
                connection_attempts: HashMap::new(),
                rate_limit_window: window,
            }),
        }
    }

    /// Record a new connection from `ip`.
    ///
    /// This increments the active connection count **and** records a
    /// timestamped connection attempt for rate-limiting purposes.
    pub fn track_connection(&self, ip: IpAddr) {
        let mut inner = self.inner.lock().unwrap();
        *inner.active_connections.entry(ip).or_insert(0) += 1;
        inner
            .connection_attempts
            .entry(ip)
            .or_default()
            .push(Instant::now());
    }

    /// Record that a connection from `ip` has been closed.
    ///
    /// Decrements the active connection count. If the count reaches zero
    /// the entry is removed to keep the map compact.
    pub fn release_connection(&self, ip: IpAddr) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(count) = inner.active_connections.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                inner.active_connections.remove(&ip);
            }
        }
    }

    /// Returns `true` if the number of active connections from `ip` is
    /// at or below `max_per_ip`.
    ///
    /// The check uses `<=` because [`validate_incoming_connection`] calls
    /// [`track_connection`] **before** this check, so the current request
    /// is already included in the count. A count equal to `max_per_ip`
    /// means the current request is allowed but no more after it.
    ///
    /// A return value of `false` means the IP has exceeded the connection
    /// limit and should be rejected.
    pub fn check_connection_limit(&self, ip: IpAddr, max_per_ip: u32) -> bool {
        let inner = self.inner.lock().unwrap();
        let count = inner.active_connections.get(&ip).copied().unwrap_or(0);
        count <= max_per_ip
    }

    /// Returns `true` if the connection-attempt rate from `ip` is within
    /// the allowed `max_per_window` threshold.
    ///
    /// The check counts how many connection attempts from `ip` occurred
    /// within the sliding window configured at construction time. The
    /// check uses `<=` because [`validate_incoming_connection`] calls
    /// [`track_connection`] **before** this check, so the current
    /// request is already included in the count. A count equal to
    /// `max_per_window` means the current request is allowed but no
    /// more after it within this window.
    ///
    /// Stale entries (older than the window) are pruned on each call to
    /// keep memory bounded, matching Go's `pruneRequests` behaviour.
    pub fn check_rate_limit(&self, ip: IpAddr, max_per_window: u32) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let window = inner.rate_limit_window;
        let now = Instant::now();
        let cutoff = now.checked_sub(window).unwrap_or(now);

        let attempts = match inner.connection_attempts.get_mut(&ip) {
            Some(v) => v,
            None => return true,
        };

        // Prune stale entries (sorted by construction, so we can
        // binary-search for the cutoff point).
        let first_valid = attempts.partition_point(|t| *t < cutoff);
        if first_valid > 0 {
            attempts.drain(..first_valid);
        }
        if attempts.is_empty() {
            inner.connection_attempts.remove(&ip);
            return true;
        }

        (attempts.len() as u32) <= max_per_window
    }

    /// Returns the number of currently active connections from `ip`.
    pub fn active_count(&self, ip: IpAddr) -> u32 {
        let inner = self.inner.lock().unwrap();
        inner.active_connections.get(&ip).copied().unwrap_or(0)
    }

    /// Returns the number of tracked IPs that have at least one active
    /// connection.
    pub fn tracked_ip_count(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.active_connections.len()
    }

    // -- Test helpers --------------------------------------------------------

    /// Record a connection attempt at a specific [`Instant`] (for tests).
    #[cfg(test)]
    fn track_connection_at(&self, ip: IpAddr, when: Instant) {
        let mut inner = self.inner.lock().unwrap();
        *inner.active_connections.entry(ip).or_insert(0) += 1;
        inner.connection_attempts.entry(ip).or_default().push(when);
    }
}

impl Default for ConnectionTracker {
    /// Creates a `ConnectionTracker` with a 1-second rate-limit window.
    fn default() -> Self {
        Self::new(Duration::from_secs(1))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    // -- Connection count tracking ------------------------------------------

    #[test]
    fn track_and_release_connection() {
        let tracker = ConnectionTracker::new(Duration::from_secs(1));
        let ip = ipv4(10, 0, 0, 1);

        assert_eq!(tracker.active_count(ip), 0);

        tracker.track_connection(ip);
        assert_eq!(tracker.active_count(ip), 1);

        tracker.track_connection(ip);
        assert_eq!(tracker.active_count(ip), 2);

        tracker.release_connection(ip);
        assert_eq!(tracker.active_count(ip), 1);

        tracker.release_connection(ip);
        assert_eq!(tracker.active_count(ip), 0);
    }

    #[test]
    fn release_without_track_is_noop() {
        let tracker = ConnectionTracker::new(Duration::from_secs(1));
        let ip = ipv4(10, 0, 0, 2);

        // Should not panic or underflow.
        tracker.release_connection(ip);
        assert_eq!(tracker.active_count(ip), 0);
    }

    #[test]
    fn release_saturates_at_zero() {
        let tracker = ConnectionTracker::new(Duration::from_secs(1));
        let ip = ipv4(10, 0, 0, 3);

        tracker.track_connection(ip);
        tracker.release_connection(ip);
        tracker.release_connection(ip); // extra release
        assert_eq!(tracker.active_count(ip), 0);
    }

    #[test]
    fn connection_limit_under() {
        let tracker = ConnectionTracker::new(Duration::from_secs(1));
        let ip = ipv4(10, 0, 0, 4);

        assert!(tracker.check_connection_limit(ip, 3));

        tracker.track_connection(ip);
        assert!(tracker.check_connection_limit(ip, 3));

        tracker.track_connection(ip);
        assert!(tracker.check_connection_limit(ip, 3));
    }

    #[test]
    fn connection_limit_at_max_allowed() {
        let tracker = ConnectionTracker::new(Duration::from_secs(1));
        let ip = ipv4(10, 0, 0, 5);

        tracker.track_connection(ip);
        tracker.track_connection(ip);
        tracker.track_connection(ip);

        // At limit (3 connections, max 3) => allowed because the current
        // request (already tracked) makes count == max.
        assert!(tracker.check_connection_limit(ip, 3));
    }

    #[test]
    fn connection_limit_exceeded() {
        let tracker = ConnectionTracker::new(Duration::from_secs(1));
        let ip = ipv4(10, 0, 0, 6);

        for _ in 0..5 {
            tracker.track_connection(ip);
        }
        // 5 > 3, so rejected.
        assert!(!tracker.check_connection_limit(ip, 3));
    }

    #[test]
    fn connection_limit_one_past_max_rejected() {
        let tracker = ConnectionTracker::new(Duration::from_secs(1));
        let ip = ipv4(10, 0, 0, 55);

        // Track max_per_ip + 1 connections — should be rejected.
        for _ in 0..4 {
            tracker.track_connection(ip);
        }
        assert!(!tracker.check_connection_limit(ip, 3));
    }

    #[test]
    fn connection_limit_after_release() {
        let tracker = ConnectionTracker::new(Duration::from_secs(1));
        let ip = ipv4(10, 0, 0, 7);

        tracker.track_connection(ip);
        tracker.track_connection(ip);
        tracker.track_connection(ip);
        tracker.track_connection(ip);
        // 4 > 3, so rejected.
        assert!(!tracker.check_connection_limit(ip, 3));

        tracker.release_connection(ip);
        // 3 <= 3, so allowed.
        assert!(tracker.check_connection_limit(ip, 3));
    }

    // -- Rate limiting ------------------------------------------------------

    #[test]
    fn rate_limit_under() {
        let tracker = ConnectionTracker::new(Duration::from_secs(10));
        let ip = ipv4(10, 0, 0, 10);

        tracker.track_connection(ip);
        tracker.track_connection(ip);

        // 2 attempts, limit 5 => allowed.
        assert!(tracker.check_rate_limit(ip, 5));
    }

    #[test]
    fn rate_limit_at_max_allowed() {
        let tracker = ConnectionTracker::new(Duration::from_secs(10));
        let ip = ipv4(10, 0, 0, 11);

        for _ in 0..5 {
            tracker.track_connection(ip);
        }

        // 5 attempts, limit 5 => allowed (current request already tracked).
        assert!(tracker.check_rate_limit(ip, 5));
    }

    #[test]
    fn rate_limit_exceeded() {
        let tracker = ConnectionTracker::new(Duration::from_secs(10));
        let ip = ipv4(10, 0, 0, 12);

        for _ in 0..10 {
            tracker.track_connection(ip);
        }

        // 10 > 5, so rejected.
        assert!(!tracker.check_rate_limit(ip, 5));
    }

    #[test]
    fn rate_limit_one_past_max_rejected() {
        let tracker = ConnectionTracker::new(Duration::from_secs(10));
        let ip = ipv4(10, 0, 0, 120);

        for _ in 0..6 {
            tracker.track_connection(ip);
        }

        // 6 > 5, so rejected.
        assert!(!tracker.check_rate_limit(ip, 5));
    }

    #[test]
    fn rate_limit_stale_entries_pruned() {
        let tracker = ConnectionTracker::new(Duration::from_millis(100));
        let ip = ipv4(10, 0, 0, 13);

        // Record old attempts in the past (before the window).
        let old = Instant::now() - Duration::from_secs(5);
        for i in 0..10 {
            tracker.track_connection_at(ip, old + Duration::from_millis(i));
        }

        // All 10 are older than 100ms window, so they should be pruned.
        assert!(tracker.check_rate_limit(ip, 5));
    }

    #[test]
    fn rate_limit_mix_of_old_and_new() {
        let tracker = ConnectionTracker::new(Duration::from_millis(500));
        let ip = ipv4(10, 0, 0, 14);

        // 10 old attempts (outside window).
        let old = Instant::now() - Duration::from_secs(5);
        for i in 0..10 {
            tracker.track_connection_at(ip, old + Duration::from_millis(i));
        }

        // 2 recent attempts (inside window).
        tracker.track_connection(ip);
        tracker.track_connection(ip);

        // Only the 2 recent should count, limit is 5 => allowed.
        assert!(tracker.check_rate_limit(ip, 5));
    }

    #[test]
    fn rate_limit_no_attempts_always_passes() {
        let tracker = ConnectionTracker::new(Duration::from_secs(1));
        let ip = ipv4(10, 0, 0, 15);

        assert!(tracker.check_rate_limit(ip, 1));
    }

    // -- Multiple IPs tracked independently ---------------------------------

    #[test]
    fn multiple_ips_independent_connection_counts() {
        let tracker = ConnectionTracker::new(Duration::from_secs(1));
        let ip_a = ipv4(192, 168, 1, 1);
        let ip_b = ipv4(192, 168, 1, 2);

        tracker.track_connection(ip_a);
        tracker.track_connection(ip_a);
        tracker.track_connection(ip_a); // 3 connections, max 2 => rejected
        tracker.track_connection(ip_b);

        assert_eq!(tracker.active_count(ip_a), 3);
        assert_eq!(tracker.active_count(ip_b), 1);

        assert!(!tracker.check_connection_limit(ip_a, 2));
        assert!(tracker.check_connection_limit(ip_b, 2));
    }

    #[test]
    fn multiple_ips_independent_rate_limits() {
        let tracker = ConnectionTracker::new(Duration::from_secs(10));
        let ip_a = ipv4(10, 1, 0, 1);
        let ip_b = ipv4(10, 1, 0, 2);

        for _ in 0..6 {
            tracker.track_connection(ip_a);
        }
        tracker.track_connection(ip_b);

        // ip_a exceeded (6 > 5), ip_b fine (1 <= 5).
        assert!(!tracker.check_rate_limit(ip_a, 5));
        assert!(tracker.check_rate_limit(ip_b, 5));
    }

    #[test]
    fn ipv6_addresses_work() {
        let tracker = ConnectionTracker::new(Duration::from_secs(1));
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);

        tracker.track_connection(ip);
        assert_eq!(tracker.active_count(ip), 1);
        assert!(tracker.check_connection_limit(ip, 2));
        assert!(tracker.check_rate_limit(ip, 5));

        tracker.release_connection(ip);
        assert_eq!(tracker.active_count(ip), 0);
    }

    // -- Metadata -----------------------------------------------------------

    #[test]
    fn tracked_ip_count() {
        let tracker = ConnectionTracker::new(Duration::from_secs(1));

        assert_eq!(tracker.tracked_ip_count(), 0);

        tracker.track_connection(ipv4(1, 1, 1, 1));
        tracker.track_connection(ipv4(2, 2, 2, 2));
        assert_eq!(tracker.tracked_ip_count(), 2);

        tracker.release_connection(ipv4(1, 1, 1, 1));
        assert_eq!(tracker.tracked_ip_count(), 1);

        tracker.release_connection(ipv4(2, 2, 2, 2));
        assert_eq!(tracker.tracked_ip_count(), 0);
    }

    #[test]
    fn default_has_one_second_window() {
        let tracker = ConnectionTracker::default();
        let ip = ipv4(10, 0, 0, 99);

        // Record an old attempt well outside the 1-second default window.
        let old = Instant::now() - Duration::from_secs(5);
        tracker.track_connection_at(ip, old);

        // Should be pruned since it's older than the 1-second window.
        assert!(tracker.check_rate_limit(ip, 1));
    }

    #[test]
    fn connection_tracker_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ConnectionTracker>();
    }
}
