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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use http::{HeaderMap, HeaderName};
use url::Url;

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
// X-Forwarded-For client-address extraction
// ---------------------------------------------------------------------------

/// Extracts the client's "real" address from an HTTP header, when the node
/// is configured to trust a reverse proxy / load balancer.
///
/// Mirrors go-algorand's `RequestTracker.getForwardedConnectionAddress`
/// (`network/requestTracker.go:483-519`), gated by the same
/// `UseXForwardedForAddressField` config knob (here:
/// `use_x_forwarded_for_address_field`):
///
/// - An empty field name disables the feature entirely: returns `None`
///   without touching `misconfigured_logged` or logging anything.
/// - When the configured field name is (case-insensitively) the standard
///   `X-Forwarded-For` header, this reads *all* occurrences of the header,
///   takes the value of the *last* occurrence, splits it on commas (a proxy
///   chain appends its own hop with a comma), and takes the last
///   (right-most, i.e. nearest-to-us-hop) entry — matching go's exact
///   "last header, last comma-separated value" parsing.
/// - Any other field name is read as a single header value via
///   `HeaderMap::get` (no comma-splitting) — matching go's
///   `header.Get(field)` fallback for a non-standard field name.
/// - An empty resolved value, or a value that fails `IpAddr` parsing, is
///   treated as "no forwarded address": returns `None`. The "empty value"
///   case is logged once per tracker lifetime (via `misconfigured_logged`,
///   matching go's `atomic.Bool` + `CompareAndSwap(false, true)` gate) to
///   warn about a proxy that isn't actually setting the configured header.
pub fn get_forwarded_connection_address(
    header: &HeaderMap,
    use_x_forwarded_for_address_field: &str,
    misconfigured_logged: &AtomicBool,
) -> Option<IpAddr> {
    if use_x_forwarded_for_address_field.is_empty() {
        return None;
    }

    let header_name = HeaderName::from_bytes(use_x_forwarded_for_address_field.as_bytes()).ok()?;

    let forwarded_for_string =
        if use_x_forwarded_for_address_field.eq_ignore_ascii_case("X-Forwarded-For") {
            // Use the last value from the last X-Forwarded-For header's list of
            // values (go-algorand's documented behavior for the standard field).
            let values: Vec<&str> = header
                .get_all(&header_name)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect();
            match values.last() {
                Some(last) => last
                    .rsplit(',')
                    .next()
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default(),
                None => String::new(),
            }
        } else {
            header
                .get(&header_name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        };

    if forwarded_for_string.is_empty() {
        if misconfigured_logged
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            tracing::warn!(
                field = %use_x_forwarded_for_address_field,
                "UseForwardedForAddressField is configured, but no value was retrieved from header"
            );
        }
        return None;
    }

    match forwarded_for_string.parse::<IpAddr>() {
        Ok(ip) => Some(ip),
        Err(_) => {
            tracing::warn!(value = %forwarded_for_string, "unable to parse origin address");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Effective remote-address resolution (X-Algorand-Location precedence)
// ---------------------------------------------------------------------------

/// Computes the best-guess effective remote address for an incoming
/// connection, mirroring go-algorand's `TrackerRequest.remoteAddress()`
/// (`network/requestTracker.go:94-115`).
///
/// `remoteAddress()` is used either for logging or as the `rootURL` when
/// registering a new peer (i.e. the address stored for future re-dialing).
/// Per go's doc comment, the rationale is:
///
/// - `other_public_addr` (go's `otherPublicAddr`) is provided by the remote
///   peer via the `X-Algorand-Location` header and cannot be trusted, but
///   can be used if `remote_host` matches its hostname. In this case it is
///   a better guess for a rootURL because it might include the peer's
///   actual listening port (as opposed to its ephemeral outbound TCP source
///   port).
/// - `remote_host` (go's `remoteHost`) is either the real address of the
///   remote peer, or a value derived from an `X-Forwarded-For`-style
///   header. It is used when it disagrees with the host portion of
///   `remote_addr`, signalling it came from a trusted proxy.
/// - `remote_addr` (go's `remoteAddr`) --- the raw "host:port" of the
///   accepted connection --- is used otherwise.
///
/// # Arguments
///
/// - `remote_addr` --- the raw `"host:port"` of the incoming connection.
/// - `remote_host` --- the resolved host only (no port): either the host
///   part of `remote_addr`, or a proxy-header-derived override.
/// - `other_public_addr` --- the raw `X-Algorand-Location` header value, if
///   present.
pub fn remote_address(
    remote_addr: &str,
    remote_host: &str,
    other_public_addr: Option<&str>,
) -> String {
    if let Some(other) = other_public_addr {
        if !other.is_empty() {
            if let Some(hostname) = parse_hostname(other) {
                if !remote_host.is_empty() && hostname == remote_host {
                    return other.to_string();
                }
            }
        }
    }

    match parse_hostname(remote_addr) {
        None => {
            // remote_addr can't be parsed, so try remote_host (there is a
            // chance it came from a proxy and has a meaningful value).
            if !remote_host.is_empty() {
                remote_host.to_string()
            } else {
                remote_addr.to_string()
            }
        }
        Some(hostname) => {
            if hostname != remote_host {
                // remote_addr's host isn't equal to remote_host, so
                // remote_host definitely came from a proxy -- use it.
                remote_host.to_string()
            } else {
                remote_addr.to_string()
            }
        }
    }
}

/// Extracts just the hostname portion of a `"host:port"` or bare-host
/// string, mirroring go's `addr.ParseHostOrURL(s).Hostname()`.
fn parse_hostname(s: &str) -> Option<String> {
    parse_host_or_url(s).and_then(|u| u.host_str().map(|h| h.to_string()))
}

/// Parses a `"host:port"` string or bare host into a [`Url`], mirroring
/// go's `addr.ParseHostOrURL`'s handling of a plain `"host:port"` (which
/// `net/url`-style parsing otherwise chokes on, reading `"host:"` as a
/// scheme) by assuming an `http://` scheme when no scheme is present.
fn parse_host_or_url(s: &str) -> Option<Url> {
    if is_host_colon_port(s) {
        return Url::parse(&format!("http://{s}")).ok();
    }
    if let Ok(url) = Url::parse(s) {
        if url.host().is_some() {
            return Some(url);
        }
        return None;
    }
    let with_scheme = Url::parse(&format!("http://{s}")).ok()?;
    if with_scheme.host().is_some() {
        Some(with_scheme)
    } else {
        None
    }
}

/// Matches go's `HostColonPortPattern` (`^[-a-zA-Z0-9.]+:\d+$`).
fn is_host_colon_port(s: &str) -> bool {
    let Some((host, port)) = s.rsplit_once(':') else {
        return false;
    };
    !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !port.is_empty()
        && port.chars().all(|c| c.is_ascii_digit())
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

    // -- X-Forwarded-For extraction (ported from go-algorand's
    // TestGetForwardedConnectionAddress, network/requestTracker_test.go:221)
    // -------------------------------------------------------------------

    #[test]
    fn forwarded_address_disabled_when_field_unset() {
        let header = HeaderMap::new();
        let logged = AtomicBool::new(false);

        let ip = get_forwarded_connection_address(&header, "", &logged);
        assert!(ip.is_none());
        // Disabled entirely: never touches the misconfigured-logging gate.
        assert!(!logged.load(Ordering::SeqCst));
    }

    #[test]
    fn forwarded_address_custom_field_missing_warns_once() {
        let header = HeaderMap::new();
        let logged = AtomicBool::new(false);

        let ip = get_forwarded_connection_address(&header, "X-Custom-Addr", &logged);
        assert!(ip.is_none());
        assert!(logged.load(Ordering::SeqCst));

        // Second call: gate already tripped, must not attempt to log again
        // (compare_exchange fails silently) but still resolves to None.
        let ip = get_forwarded_connection_address(&header, "X-Custom-Addr", &logged);
        assert!(ip.is_none());
    }

    #[test]
    fn forwarded_address_custom_field_single_value_parses() {
        let mut header = HeaderMap::new();
        header.insert("X-Custom-Addr", "123.123.123.123".parse().unwrap());
        let logged = AtomicBool::new(false);

        let ip = get_forwarded_connection_address(&header, "X-Custom-Addr", &logged);
        assert_eq!(ip, Some("123.123.123.123".parse::<IpAddr>().unwrap()));
        assert!(!logged.load(Ordering::SeqCst));
    }

    #[test]
    fn forwarded_address_custom_field_list_not_split() {
        // A non-standard field name is read as a single value via `get`,
        // with no comma-splitting — go's "original behavior since the
        // Release" per the upstream test's own comment.
        let mut header = HeaderMap::new();
        header.insert(
            "X-Custom-Addr",
            "123.123.123.123, 234.234.234.234".parse().unwrap(),
        );
        let logged = AtomicBool::new(false);

        let ip = get_forwarded_connection_address(&header, "X-Custom-Addr", &logged);
        assert!(ip.is_none());
    }

    #[test]
    fn forwarded_address_x_forwarded_for_empty_warns() {
        let header = HeaderMap::new();
        let logged = AtomicBool::new(false);

        let ip = get_forwarded_connection_address(&header, "X-Forwarded-For", &logged);
        assert!(ip.is_none());
        assert!(logged.load(Ordering::SeqCst));
    }

    #[test]
    fn forwarded_address_x_forwarded_for_single_value() {
        let mut header = HeaderMap::new();
        header.insert("X-Forwarded-For", "123.123.123.123".parse().unwrap());
        let logged = AtomicBool::new(false);

        let ip = get_forwarded_connection_address(&header, "X-Forwarded-For", &logged);
        assert_eq!(ip, Some("123.123.123.123".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn forwarded_address_x_forwarded_for_list_uses_last_value() {
        // Single header occurrence with a comma-separated proxy chain: the
        // last (right-most) address is used — this is the new behavior go's
        // test comment calls out explicitly.
        let mut header = HeaderMap::new();
        header.insert(
            "X-Forwarded-For",
            "123.123.123.123, 234.234.234.234".parse().unwrap(),
        );
        let logged = AtomicBool::new(false);

        let ip = get_forwarded_connection_address(&header, "X-Forwarded-For", &logged);
        assert_eq!(ip, Some("234.234.234.234".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn forwarded_address_x_forwarded_for_multiple_headers_uses_last_occurrence() {
        // Multiple X-Forwarded-For header lines: use the last occurrence's
        // value (then the last comma-separated entry within it).
        let mut header = HeaderMap::new();
        header.append("X-Forwarded-For", "10.0.0.1".parse().unwrap());
        header.append(
            "X-Forwarded-For",
            "123.123.123.123, 234.234.234.234".parse().unwrap(),
        );
        let logged = AtomicBool::new(false);

        let ip = get_forwarded_connection_address(&header, "X-Forwarded-For", &logged);
        assert_eq!(ip, Some("234.234.234.234".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn forwarded_address_field_name_case_insensitive() {
        // go canonicalizes via textproto.CanonicalMIMEHeaderKey before
        // comparing to "X-Forwarded-For"; a lowercase config value must
        // still hit the comma-splitting path.
        let mut header = HeaderMap::new();
        header.insert("x-forwarded-for", "1.2.3.4, 5.6.7.8".parse().unwrap());
        let logged = AtomicBool::new(false);

        let ip = get_forwarded_connection_address(&header, "x-forwarded-for", &logged);
        assert_eq!(ip, Some("5.6.7.8".parse::<IpAddr>().unwrap()));
    }

    // -- remote_address (X-Algorand-Location precedence, ported from go's
    // TestRemoteAddress, network/requestTracker_test.go:180) ---------------

    #[test]
    fn remote_address_no_header_uses_remote_addr() {
        // tr := makeTrackerRequest("127.0.0.1:444", "", "", time.Now())
        // remoteHost derived from remoteAddr: "127.0.0.1"
        // require.Equal(t, "127.0.0.1:444", tr.remoteAddress())
        assert_eq!(
            remote_address("127.0.0.1:444", "127.0.0.1", None),
            "127.0.0.1:444"
        );
    }

    #[test]
    fn remote_address_proxy_remote_host_used_when_it_disagrees() {
        // remoteHost set to something else via X-Forwarded-For HTTP headers.
        // require.Equal(t, "10.0.0.1", tr.remoteAddress())
        assert_eq!(
            remote_address("127.0.0.1:444", "10.0.0.1", None),
            "10.0.0.1"
        );
    }

    #[test]
    fn remote_address_header_used_when_hostname_matches_remote_host() {
        // otherPublicAddr is set via X-Algorand-Location HTTP header and
        // matches to the remoteHost.
        // require.Equal(t, "10.0.0.1:555", tr.remoteAddress())
        assert_eq!(
            remote_address("127.0.0.1:444", "10.0.0.1", Some("10.0.0.1:555")),
            "10.0.0.1:555"
        );
    }

    #[test]
    fn remote_address_header_ignored_when_hostname_does_not_match() {
        // otherPublicAddr does not match remoteHost -- ignored, falls back
        // to remoteAddr (whose hostname matches remoteHost here).
        // require.Equal(t, "127.0.0.1:444", tr.remoteAddress())
        assert_eq!(
            remote_address("127.0.0.1:444", "127.0.0.1", Some("127.0.0.99:555")),
            "127.0.0.1:444"
        );
    }

    #[test]
    fn remote_address_unparseable_remote_addr_falls_back_to_remote_host() {
        assert_eq!(
            remote_address("not a valid addr :: at all", "10.0.0.1", None),
            "10.0.0.1"
        );
    }

    #[test]
    fn remote_address_empty_header_ignored() {
        assert_eq!(
            remote_address("127.0.0.1:444", "127.0.0.1", Some("")),
            "127.0.0.1:444"
        );
    }
}
