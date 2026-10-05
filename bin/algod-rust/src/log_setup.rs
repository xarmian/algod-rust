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
//! rate-limited: the first few events per window pass, the rest are dropped,
//! and one summary line reports how many. An operator whose `RUST_LOG` names
//! that target (or a parent of it) gets unfiltered output.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use tracing::{Event, Metadata, Subscriber};
use tracing_subscriber::filter::FilterExt;
use tracing_subscriber::layer::{Context, Filter, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

/// Target of the validator's per-recursion ERROR.
const NOISY_TARGET: &str = "hickory_proto::dnssec::dnssec_dns_handle";
/// Events of [`NOISY_TARGET`] allowed through per window.
const BURST: u32 = 5;
/// Rate-limit window.
const WINDOW: Duration = Duration::from_secs(60);

/// True when a `RUST_LOG`-style `spec` has a directive whose target is
/// [`NOISY_TARGET`] or one of its ancestors (`hickory_proto`,
/// `hickory_proto::dnssec`, ...), i.e. the operator asked for that output.
fn names_noisy_target(spec: &str) -> bool {
    const LEVELS: [&str; 6] = ["off", "error", "warn", "info", "debug", "trace"];
    spec.split(',').any(|directive| {
        let target = directive.split('=').next().unwrap_or("");
        let target = target.split(['[', '{']).next().unwrap_or("").trim();
        if target.is_empty()
            || LEVELS.iter().any(|l| l.eq_ignore_ascii_case(target))
            || target.chars().all(|c| c.is_ascii_digit())
        {
            return false;
        }
        NOISY_TARGET == target || NOISY_TARGET.starts_with(&format!("{target}::"))
    })
}

/// Result of interpreting `RUST_LOG`.
#[derive(Debug)]
struct LogSetup {
    /// Filter directives to install.
    filter_spec: String,
    /// Whether [`NOISY_TARGET`] is rate-limited.
    rate_limit: bool,
    /// One-time warning to print (bad `RUST_LOG`).
    warning: Option<String>,
}

impl LogSetup {
    /// Unset or blank `RUST_LOG` means `info`; an unparsable one warns and
    /// falls back to `info`. The rate limit applies unless the operator
    /// named the noisy target.
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

/// Decision for one event of the rate-limited target.
#[derive(Debug, PartialEq, Eq)]
enum Admit {
    Pass,
    Drop,
    /// Pass, and the previous window dropped this many events.
    PassReportingDrops(u64),
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

    fn admit(&self, now: Instant) -> Admit {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        match st.0 {
            Some(start) if now < start + self.window => {
                if st.1 < self.burst {
                    st.1 += 1;
                    Admit::Pass
                } else {
                    st.2 += 1;
                    Admit::Drop
                }
            }
            _ => {
                let dropped = st.2;
                *st = (Some(now), 1, 0);
                if dropped > 0 {
                    Admit::PassReportingDrops(dropped)
                } else {
                    Admit::Pass
                }
            }
        }
    }
}

/// Per-layer filter applying [`RateLimiter`] to [`NOISY_TARGET`] events.
struct NoisyTargetLimiter {
    enabled: bool,
    limiter: RateLimiter,
}

impl<S: Subscriber> Filter<S> for NoisyTargetLimiter {
    fn enabled(&self, _: &Metadata<'_>, _: &Context<'_, S>) -> bool {
        true
    }

    fn event_enabled(&self, event: &Event<'_>, _: &Context<'_, S>) -> bool {
        if !self.enabled || event.metadata().target() != NOISY_TARGET {
            return true;
        }
        match self.limiter.admit(Instant::now()) {
            Admit::Pass => true,
            Admit::Drop => false,
            Admit::PassReportingDrops(n) => {
                // stderr, not tracing: emitting an event from inside a
                // filter would re-enter the subscriber.
                eprintln!(
                    "algod-rust: rate-limited {NOISY_TARGET}: suppressed {n} events in the previous {}s window (set RUST_LOG={NOISY_TARGET}=error to see all)",
                    WINDOW.as_secs()
                );
                true
            }
        }
    }
}

/// Install the global subscriber from `RUST_LOG`.
pub fn init() {
    let raw = std::env::var("RUST_LOG").ok();
    let setup = LogSetup::resolve(raw.as_deref());
    if let Some(w) = &setup.warning {
        eprintln!("algod-rust: {w}");
    }
    let env = EnvFilter::try_new(&setup.filter_spec).unwrap_or_else(|_| EnvFilter::new("info"));
    let limiter = NoisyTargetLimiter {
        enabled: setup.rate_limit,
        limiter: RateLimiter::new(BURST, WINDOW),
    };
    let layer = tracing_subscriber::fmt::layer().with_filter(env.and(limiter));
    tracing_subscriber::registry().with(layer).init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_detection_matches_prefix_targets() {
        for spec in [
            "hickory_proto=trace",
            "hickory_proto::dnssec=trace",
            "hickory_proto::dnssec::dnssec_dns_handle=error",
            "info,hickory_proto=debug",
            " info , hickory_proto::dnssec=warn ",
            "hickory_proto",
        ] {
            assert!(names_noisy_target(spec), "{spec} must count as an override");
        }
        for spec in [
            "info",
            "DEBUG",
            "algod_rust=debug",
            "hickory_resolver=debug",
            "hickory_proto::dnssec_other=trace",
            "hickory_proto::dnssec::dnssec_dns_handle::deeper=trace",
            "hickory_proto::udp=trace",
        ] {
            assert!(!names_noisy_target(spec), "{spec} must not count");
        }
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
    fn explicit_filter_is_kept_and_override_disables_limit() {
        let s = LogSetup::resolve(Some("warn"));
        assert_eq!(s.filter_spec, "warn");
        assert!(s.rate_limit);
        let s = LogSetup::resolve(Some("info,hickory_proto=trace"));
        assert_eq!(s.filter_spec, "info,hickory_proto=trace");
        assert!(!s.rate_limit);
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
    fn limiter_passes_burst_drops_rest_and_reports_next_window() {
        let t0 = Instant::now();
        let w = Duration::from_secs(60);
        let l = RateLimiter::new(3, w);
        for _ in 0..3 {
            assert_eq!(l.admit(t0), Admit::Pass);
        }
        assert_eq!(l.admit(t0 + Duration::from_secs(1)), Admit::Drop);
        assert_eq!(l.admit(t0 + Duration::from_secs(2)), Admit::Drop);
        assert_eq!(
            l.admit(t0 + w + Duration::from_secs(1)),
            Admit::PassReportingDrops(2)
        );
        // The new window starts with a fresh burst and no stale drop count.
        assert_eq!(l.admit(t0 + w + Duration::from_secs(2)), Admit::Pass);
    }

    #[test]
    fn limiter_without_drops_never_reports() {
        let t0 = Instant::now();
        let l = RateLimiter::new(2, Duration::from_secs(10));
        assert_eq!(l.admit(t0), Admit::Pass);
        assert_eq!(l.admit(t0 + Duration::from_secs(11)), Admit::Pass);
    }

    /// Counts events reaching it.
    struct Count(std::sync::Arc<std::sync::atomic::AtomicUsize>);
    impl<S: Subscriber> Layer<S> for Count {
        fn on_event(&self, _: &Event<'_>, _: Context<'_, S>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// The filter, composed as `init` composes it, really drops the noisy
    /// target after the burst while leaving other targets untouched.
    #[test]
    fn composed_filter_limits_only_the_noisy_target() {
        let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let limiter = NoisyTargetLimiter {
            enabled: true,
            limiter: RateLimiter::new(2, Duration::from_secs(3600)),
        };
        let sub = tracing_subscriber::registry()
            .with(Count(seen.clone()).with_filter(EnvFilter::new("info").and(limiter)));
        tracing::subscriber::with_default(sub, || {
            for _ in 0..10 {
                tracing::error!(target: "hickory_proto::dnssec::dnssec_dns_handle", "depth");
            }
            for _ in 0..3 {
                tracing::error!(target: "algo_network::srv_resolver", "other");
            }
        });
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 2 + 3);
    }
}
