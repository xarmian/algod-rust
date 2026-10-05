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

//! Process-wide logging setup (issue #1676).
//!
//! hickory's DNSSEC validator logs `exceeded max validation depth` at ERROR
//! once per validation recursion: a spinning lookup produced about 58k such
//! lines per 15 s stage (232k in one mainnet soak start). Silencing the
//! target would also hide genuine DNSSEC failures, so instead the target is
//! rate-limited: the first few events per window pass and the rest are
//! dropped. A small background thread reports the number of dropped events
//! through `tracing` once the window has ended, even if no further event
//! arrives (a single burst followed by silence is the real case). An operator
//! whose `RUST_LOG` asks for more than the default on that target (or an
//! ancestor of it) gets unfiltered output.

use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use tracing::{Event, Metadata, Subscriber};
use tracing_subscriber::filter::FilterExt;
use tracing_subscriber::layer::{Context, Filter, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

/// Module paths of the validator's per-recursion ERROR (the lockfile carries
/// both hickory generations).
const NOISY_TARGET_PATHS: [&str; 2] = [
    "hickory_proto::dnssec::dnssec_dns_handle",
    "hickory_proto::xfer::dnssec_dns_handle",
];
/// Events of the noisy target allowed through per window.
const BURST: u32 = 5;
/// Rate-limit window.
const WINDOW: Duration = Duration::from_secs(60);
/// How often the summary thread checks for an ended window.
const SUMMARY_TICK: Duration = Duration::from_secs(1);

/// True for an event target emitted by the validator handle, whichever
/// hickory generation's module path it carries.
fn is_noisy_target(target: &str) -> bool {
    target.starts_with("hickory_proto") && target.ends_with("dnssec_dns_handle")
}

/// Split a `RUST_LOG`-style spec on commas that are not nested inside
/// `[...]` / `{...}` span and field filters.
fn split_directives(spec: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut start) = (0i32, 0usize);
    for (i, c) in spec.char_indices() {
        match c {
            '[' | '{' => depth += 1,
            ']' | '}' => depth -= 1,
            ',' if depth <= 0 => {
                out.push(&spec[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&spec[start..]);
    out.into_iter()
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .collect()
}

/// Split one directive into `(target, level)`; the level is whatever follows
/// the first `=` that is not nested in a span/field filter.
fn directive_target_and_level(directive: &str) -> (&str, Option<&str>) {
    let mut depth = 0i32;
    let mut eq = None;
    for (i, c) in directive.char_indices() {
        match c {
            '[' | '{' => depth += 1,
            ']' | '}' => depth -= 1,
            '=' if depth <= 0 => {
                eq = Some(i);
                break;
            }
            _ => {}
        }
    }
    let head = eq.map_or(directive, |i| &directive[..i]);
    let target = head.split(['[', '{']).next().unwrap_or("").trim();
    (target, eq.map(|i| directive[i + 1..].trim()))
}

/// A directive level that asks for more than the default `info`-and-above
/// output on the target. No level means trace.
fn level_is_verbose(level: Option<&str>) -> bool {
    match level {
        None => true,
        Some(l) => matches!(
            l.to_ascii_lowercase().as_str(),
            "trace" | "debug" | "info" | "5" | "4" | "3"
        ),
    }
}

/// True when a `RUST_LOG`-style `spec` has a verbose directive whose target
/// is the noisy target or one of its ancestors (`hickory_proto`,
/// `hickory_proto::dnssec`, ...), i.e. the operator asked for that output.
/// Quieting directives (`warn`, `error`, `off`) do not count: the flood is
/// ERROR level and would pass them, so the limiter must stay on.
fn names_noisy_target(spec: &str) -> bool {
    const LEVELS: [&str; 6] = ["off", "error", "warn", "info", "debug", "trace"];
    split_directives(spec).into_iter().any(|directive| {
        let (target, level) = directive_target_and_level(directive);
        if target.is_empty()
            || LEVELS.iter().any(|l| l.eq_ignore_ascii_case(target))
            || target.chars().all(|c| c.is_ascii_digit())
        {
            return false;
        }
        let ancestor = NOISY_TARGET_PATHS
            .iter()
            .any(|p| *p == target || p.starts_with(&format!("{target}::")));
        ancestor && level_is_verbose(level)
    })
}

/// Result of interpreting `RUST_LOG`.
#[derive(Debug)]
struct LogSetup {
    /// Filter directives to install.
    filter_spec: String,
    /// Whether the noisy target is rate-limited.
    rate_limit: bool,
    /// One-time warning to print (bad `RUST_LOG`).
    warning: Option<String>,
}

impl LogSetup {
    /// Unset or blank `RUST_LOG` means `info` (the previous initializer,
    /// `EnvFilter::try_from_default_env`, turned a blank value into an empty
    /// filter); an unparsable one warns and falls back to `info`. The rate
    /// limit applies unless the operator asked for verbose output on the
    /// noisy target.
    fn resolve(raw: Option<&str>) -> Self {
        let raw = raw.map(str::trim).filter(|v| !v.is_empty());
        let (filter_spec, warning) = match raw {
            None => ("info".to_string(), None),
            Some(v) => match EnvFilter::try_new(v) {
                Ok(_) => (v.to_string(), None),
                Err(e) => (
                    "info".to_string(),
                    Some(format!(
                        "ignoring invalid RUST_LOG value {v:?} ({e}); using \"info\""
                    )),
                ),
            },
        };
        let rate_limit = !names_noisy_target(&filter_spec);
        Self {
            filter_spec,
            rate_limit,
            warning,
        }
    }
}

/// Fixed-window limiter: at most `burst` events per `window`.
struct RateLimiter {
    burst: u32,
    window: Duration,
    state: Mutex<(Option<Instant>, u32, u64)>, // (window start, passed, dropped)
}

impl RateLimiter {
    fn new(burst: u32, window: Duration) -> Self {
        Self {
            burst,
            window,
            state: Mutex::new((None, 0, 0)),
        }
    }

    /// True when the event may pass. Events dropped in an earlier window that
    /// was never flushed stay counted.
    fn admit(&self, now: Instant) -> bool {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        match st.0 {
            Some(start) if now < start + self.window => {
                if st.1 < self.burst {
                    st.1 += 1;
                    true
                } else {
                    st.2 += 1;
                    false
                }
            }
            _ => {
                *st = (Some(now), 1, st.2);
                true
            }
        }
    }

    /// If the current window has ended with dropped events, return (and
    /// reset) their count so it is reported exactly once.
    fn flush(&self, now: Instant) -> Option<u64> {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        match st.0 {
            Some(start) if now >= start + self.window && st.2 > 0 => {
                let dropped = st.2;
                *st = (None, 0, 0);
                Some(dropped)
            }
            _ => None,
        }
    }
}

/// Background thread that calls `report(dropped)` once a window with drops
/// has ended, with no further event required. It holds only a weak
/// reference, so it exits once the limiter is dropped.
fn spawn_summary_ticker(
    limiter: &Arc<RateLimiter>,
    tick: Duration,
    report: impl Fn(u64) + Send + 'static,
) -> std::thread::JoinHandle<()> {
    let weak: Weak<RateLimiter> = Arc::downgrade(limiter);
    std::thread::Builder::new()
        .name("log-rate-summary".into())
        .spawn(move || loop {
            std::thread::sleep(tick);
            let Some(limiter) = weak.upgrade() else {
                break;
            };
            if let Some(n) = limiter.flush(Instant::now()) {
                report(n);
            }
        })
        .expect("spawn log rate-limit summary thread")
}

/// Per-layer filter applying [`RateLimiter`] to noisy-target events.
struct NoisyTargetLimiter {
    enabled: bool,
    limiter: Arc<RateLimiter>,
}

impl<S: Subscriber> Filter<S> for NoisyTargetLimiter {
    fn enabled(&self, _: &Metadata<'_>, _: &Context<'_, S>) -> bool {
        true
    }

    fn event_enabled(&self, event: &Event<'_>, _: &Context<'_, S>) -> bool {
        if !self.enabled || !is_noisy_target(event.metadata().target()) {
            return true;
        }
        self.limiter.admit(Instant::now())
    }
}

/// Install the global subscriber from `RUST_LOG`.
///
/// A blank `RUST_LOG` is treated as unset (`info`), unlike the earlier
/// `EnvFilter::try_from_default_env` initializer, which produced an empty
/// filter; `kmd-rust` still uses that pattern and is unchanged. An invalid
/// value prints one warning to stderr and falls back to `info`.
pub fn init() {
    let raw = std::env::var("RUST_LOG").ok();
    let setup = LogSetup::resolve(raw.as_deref());
    if let Some(w) = &setup.warning {
        eprintln!("algod-rust: {w}");
    }
    let env = EnvFilter::try_new(&setup.filter_spec).unwrap_or_else(|_| EnvFilter::new("info"));
    let limiter = Arc::new(RateLimiter::new(BURST, WINDOW));
    if setup.rate_limit {
        // Detached on purpose: it lives as long as the process.
        drop(spawn_summary_ticker(&limiter, SUMMARY_TICK, |n| {
            tracing::warn!(
                target: "algod_rust::log_setup",
                suppressed = n,
                window_secs = WINDOW.as_secs(),
                "rate-limited hickory dnssec_dns_handle errors: suppressed {n} events in the \
                 last window (set RUST_LOG=hickory_proto=debug to see all)"
            );
        }));
    }
    let filter = NoisyTargetLimiter {
        enabled: setup.rate_limit,
        limiter,
    };
    let layer = tracing_subscriber::fmt::layer().with_filter(env.and(filter));
    tracing_subscriber::registry().with(layer).init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn override_matrix_only_verbose_directives_disable_the_limiter() {
        for spec in [
            // verbose levels on the target or an ancestor
            "hickory_proto=trace",
            "hickory_proto=debug",
            "hickory_proto=info",
            "hickory_proto=INFO",
            "hickory_proto=5",
            "hickory_proto::dnssec=trace",
            "hickory_proto::dnssec::dnssec_dns_handle=info",
            "hickory_proto::xfer::dnssec_dns_handle=debug",
            // no level means trace
            "hickory_proto",
            "info,hickory_proto=debug",
            " info , hickory_proto::dnssec=debug ",
            // commas inside span/field filters must not confuse the parse
            "info,foo[span{a=1,b=2}]=debug,hickory_proto=debug",
        ] {
            assert!(names_noisy_target(spec), "{spec} must disable the limiter");
        }
        for spec in [
            // quieting directives keep the limiter: the flood is ERROR and
            // would otherwise return in full
            "hickory_proto=warn",
            "hickory_proto=WARN",
            "hickory_proto=error",
            "hickory_proto=off",
            "hickory_proto=1",
            "hickory_proto::dnssec::dnssec_dns_handle=error",
            " info , hickory_proto::dnssec=warn ",
            // unrelated targets
            "info",
            "DEBUG",
            "algod_rust=debug",
            "hickory_resolver=debug",
            "hickory_proto::dnssec_other=trace",
            "hickory_proto::dnssec::dnssec_dns_handle::deeper=trace",
            "hickory_proto::udp=trace",
            "info,foo[span{a=1,b=2}]=debug",
        ] {
            assert!(!names_noisy_target(spec), "{spec} must keep the limiter");
        }
    }

    #[test]
    fn splitter_respects_bracket_and_brace_nesting() {
        assert_eq!(
            split_directives("info,foo[span{a=1,b=2}]=debug,hickory_proto=debug"),
            vec!["info", "foo[span{a=1,b=2}]=debug", "hickory_proto=debug"]
        );
        assert_eq!(split_directives(""), Vec::<&str>::new());
    }

    #[test]
    fn noisy_target_predicate_covers_both_hickory_versions() {
        assert!(is_noisy_target("hickory_proto::dnssec::dnssec_dns_handle"));
        assert!(is_noisy_target("hickory_proto::xfer::dnssec_dns_handle"));
        assert!(!is_noisy_target("hickory_proto::dnssec::verifier"));
        assert!(!is_noisy_target("hickory_resolver::dnssec_dns_handle"));
        assert!(!is_noisy_target("algo_network::srv_resolver"));
    }

    #[test]
    fn empty_or_unset_rust_log_gets_info_and_the_policy() {
        for raw in [None, Some(""), Some("   ")] {
            let s = LogSetup::resolve(raw);
            assert_eq!(s.filter_spec, "info");
            assert!(s.rate_limit);
            assert!(s.warning.is_none());
        }
    }

    #[test]
    fn explicit_filter_is_kept_and_verbose_override_disables_limit() {
        let s = LogSetup::resolve(Some("warn"));
        assert_eq!(s.filter_spec, "warn");
        assert!(s.rate_limit);
        let s = LogSetup::resolve(Some("info,hickory_proto=trace"));
        assert_eq!(s.filter_spec, "info,hickory_proto=trace");
        assert!(!s.rate_limit);
        let s = LogSetup::resolve(Some("info,hickory_proto=warn"));
        assert!(s.rate_limit, "a quieting directive keeps the limiter");
    }

    #[test]
    fn invalid_rust_log_warns_and_falls_back_to_info_with_policy() {
        let s = LogSetup::resolve(Some("info,foo[bar=trace"));
        assert_eq!(s.filter_spec, "info");
        assert!(s.rate_limit);
        let w = s.warning.expect("a warning naming the bad value");
        assert!(w.contains("info,foo[bar=trace"), "{w}");
    }

    #[test]
    fn limiter_passes_burst_and_drops_the_rest() {
        let t0 = Instant::now();
        let l = RateLimiter::new(3, Duration::from_secs(60));
        for _ in 0..3 {
            assert!(l.admit(t0));
        }
        assert!(!l.admit(t0 + Duration::from_secs(1)));
        // A new window starts with a fresh burst.
        assert!(l.admit(t0 + Duration::from_secs(61)));
    }

    #[test]
    fn burst_then_silence_is_reported_exactly_once_by_flush() {
        let t0 = Instant::now();
        let w = Duration::from_secs(60);
        let l = RateLimiter::new(5, w);
        for i in 0..15 {
            l.admit(t0 + Duration::from_millis(i));
        }
        // Still inside the window: nothing to report yet.
        assert_eq!(l.flush(t0 + w - Duration::from_secs(1)), None);
        // Window over and no further events: the drops are reported once.
        assert_eq!(l.flush(t0 + w + Duration::from_secs(1)), Some(10));
        assert_eq!(l.flush(t0 + w + Duration::from_secs(2)), None);
        // Nothing dropped, nothing to report.
        let quiet = RateLimiter::new(5, w);
        quiet.admit(t0);
        assert_eq!(quiet.flush(t0 + w + Duration::from_secs(1)), None);
    }

    #[test]
    fn drops_carried_into_a_new_window_are_not_lost() {
        let t0 = Instant::now();
        let w = Duration::from_secs(60);
        let l = RateLimiter::new(1, w);
        l.admit(t0);
        l.admit(t0); // dropped
        assert!(l.admit(t0 + w + Duration::from_secs(1))); // new window, no flush ran
        assert_eq!(l.flush(t0 + w * 3), Some(1));
    }

    #[test]
    fn ticker_reports_a_burst_without_further_events_and_exits_on_drop() {
        let l = Arc::new(RateLimiter::new(2, Duration::from_millis(50)));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let handle = spawn_summary_ticker(&l, Duration::from_millis(10), move |n| {
            sink.lock().unwrap().push(n)
        });
        for _ in 0..10 {
            l.admit(Instant::now());
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while seen.lock().unwrap().is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(*seen.lock().unwrap(), vec![8], "exactly one summary");
        drop(l);
        handle
            .join()
            .expect("ticker exits once the limiter is gone");
    }

    /// Counts events reaching it.
    struct Count(Arc<std::sync::atomic::AtomicUsize>);
    impl<S: Subscriber> Layer<S> for Count {
        fn on_event(&self, _: &Event<'_>, _: Context<'_, S>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// The filter, composed as `init` composes it, really drops the noisy
    /// target after the burst while leaving other targets untouched.
    #[test]
    fn composed_filter_limits_only_the_noisy_target() {
        let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let limiter = NoisyTargetLimiter {
            enabled: true,
            limiter: Arc::new(RateLimiter::new(2, Duration::from_secs(3600))),
        };
        let sub = tracing_subscriber::registry()
            .with(Count(seen.clone()).with_filter(EnvFilter::new("info").and(limiter)));
        tracing::subscriber::with_default(sub, || {
            for _ in 0..10 {
                tracing::error!(target: "hickory_proto::dnssec::dnssec_dns_handle", "depth");
            }
            for _ in 0..4 {
                tracing::error!(target: "hickory_proto::xfer::dnssec_dns_handle", "depth");
            }
            for _ in 0..3 {
                tracing::error!(target: "algo_network::srv_resolver", "other");
            }
        });
        // 2 from the burst (the 0.24-style path shares the same budget) + 3.
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 2 + 3);
    }
}
