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
//! (at ERROR, like the events themselves) once the window has ended, even if
//! no further event arrives. Drops of a window still open when the process
//! exits are not reported.
//!
//! Only an explicit `RUST_LOG` directive whose target is the noisy target or
//! a string prefix of it (`hickory_proto=debug`, `hickory=trace`) at
//! trace/debug (or with no level) disables the limiter. A bare global level
//! (`RUST_LOG=debug`) does not: debugging everything must not bring back the
//! flood from this one target. Everything else about `RUST_LOG` handling is
//! unchanged from the previous `EnvFilter::try_from_default_env` initializer.

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

/// Whether a directive target is really a bare level word (or number), i.e.
/// a global level directive such as `debug`.
fn is_level_word(t: &str) -> bool {
    const LEVELS: [&str; 6] = ["off", "error", "warn", "info", "debug", "trace"];
    LEVELS.iter().any(|l| l.eq_ignore_ascii_case(t)) || t.chars().all(|c| c.is_ascii_digit())
}

/// A directive level that asks for more than the default output on the
/// target: only trace/debug (5/4). `info` is the default and the flood is
/// ERROR level, so `info` (3) keeps the limiter on. No level means trace.
fn level_is_verbose(level: Option<&str>) -> bool {
    match level {
        None => true,
        Some(l) => matches!(
            l.to_ascii_lowercase().as_str(),
            "trace" | "debug" | "5" | "4"
        ),
    }
}

/// True when `spec` has an explicit directive asking for verbose (trace or
/// debug) output on the noisy target. Targets match like `EnvFilter` matches
/// them, by plain string prefix (`hickory`, `hickory_p`, `hickory_proto::dnssec`
/// all cover it); the most specific (longest) such directive decides, later
/// winning ties. Bare global levels are ignored (see the module docs).
fn names_noisy_target(spec: &str) -> bool {
    let mut best: Option<(usize, bool)> = None;
    for directive in split_directives(spec) {
        let (target, level) = directive_target_and_level(directive);
        if target.is_empty() || (is_level_word(target) && level.is_none()) {
            continue;
        }
        if !NOISY_TARGET_PATHS.iter().any(|p| p.starts_with(target)) {
            continue;
        }
        let verbose = level_is_verbose(level);
        match best {
            Some((len, _)) if target.len() < len => {}
            _ => best = Some((target.len(), verbose)),
        }
    }
    best.is_some_and(|(_, verbose)| verbose)
}

/// Result of interpreting `RUST_LOG`.
#[derive(Debug)]
struct LogSetup {
    /// Filter directives to install.
    filter_spec: String,
    /// Whether the noisy target is rate-limited.
    rate_limit: bool,
}

impl LogSetup {
    /// Same semantics as the previous
    /// `EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))`:
    /// unset is `info`, a value is parsed as given (so blank stays whatever
    /// `EnvFilter` makes of it), an unparsable one silently falls back to
    /// `info`. The limiter applies unless the operator explicitly asked for
    /// verbose output on the noisy target.
    fn resolve(raw: Option<&str>) -> Self {
        let filter_spec = match raw {
            Some(v) if EnvFilter::try_new(v).is_ok() => v.to_string(),
            _ => "info".to_string(),
        };
        let rate_limit = !names_noisy_target(&filter_spec);
        Self {
            filter_spec,
            rate_limit,
        }
    }
}

/// Limiter state: all mutated under one lock.
#[derive(Default)]
struct LimiterState {
    /// Start of the current window, if one is open.
    start: Option<Instant>,
    /// Events passed in the current window.
    passed: u32,
    /// Events dropped in the current window.
    dropped: u64,
    /// Drops of already-ended windows not yet reported.
    pending: u64,
}

/// Fixed-window limiter: at most `burst` events per `window`. The window
/// boundary does not depend on events: whichever of `admit`/`flush` first
/// observes the ended window rolls it, moving its drop count to `pending`
/// (reported by `flush`) and resetting before anything else is counted.
struct RateLimiter {
    burst: u32,
    window: Duration,
    state: Mutex<LimiterState>,
}

impl RateLimiter {
    fn new(burst: u32, window: Duration) -> Self {
        Self {
            burst,
            window,
            state: Mutex::new(LimiterState::default()),
        }
    }

    fn roll(&self, st: &mut LimiterState, now: Instant) {
        if let Some(start) = st.start {
            if now >= start + self.window {
                st.pending += st.dropped;
                st.dropped = 0;
                st.passed = 0;
                st.start = None;
            }
        }
    }

    /// True when the event may pass.
    fn admit(&self, now: Instant) -> bool {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.roll(&mut st, now);
        if st.start.is_none() {
            st.start = Some(now);
        }
        if st.passed < self.burst {
            st.passed += 1;
            true
        } else {
            st.dropped += 1;
            false
        }
    }

    /// Return (and reset) the drop count of ended windows, so each is
    /// reported once, with no further event required.
    fn flush(&self, now: Instant) -> Option<u64> {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.roll(&mut st, now);
        (st.pending > 0).then(|| std::mem::take(&mut st.pending))
    }
}

/// Daemon thread that calls `report(dropped)` once a window with drops has
/// ended, with no further event required. It holds only a weak reference so
/// that tests' limiters let it go; in production the global subscriber keeps
/// the limiter for the life of the process.
fn spawn_summary_ticker(
    limiter: &Arc<RateLimiter>,
    tick: Duration,
    report: impl Fn(u64) + Send + 'static,
) -> std::io::Result<()> {
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
        .map(drop)
}

/// The suppression notice. ERROR, like the events it summarizes, so it
/// survives any filter that lets those events through (`RUST_LOG=error`).
fn emit_summary(dropped: u64) {
    tracing::error!(
        target: "algod_rust::log_setup",
        suppressed = dropped,
        window_secs = WINDOW.as_secs(),
        "rate-limited hickory dnssec_dns_handle errors: suppressed {dropped} events in the \
         last window (set RUST_LOG=hickory_proto=debug to see all)"
    );
}

/// Build the limiter when `rate_limit` is on, starting its summary thread
/// through `spawn`. If the thread cannot start (e.g. a container pids
/// limit) no limiter is installed at all: events then pass unlimited rather
/// than being dropped with no summary ever; one stderr line says so.
fn build_limiter(
    rate_limit: bool,
    spawn: impl FnOnce(&Arc<RateLimiter>) -> std::io::Result<()>,
) -> Option<Arc<RateLimiter>> {
    if !rate_limit {
        return None;
    }
    let limiter = Arc::new(RateLimiter::new(BURST, WINDOW));
    match spawn(&limiter) {
        Ok(()) => Some(limiter),
        Err(e) => {
            eprintln!(
                "algod-rust: could not start the log rate-limit summary thread ({e}); \
                 hickory dnssec_dns_handle errors will not be rate-limited"
            );
            None
        }
    }
}

/// Per-layer filter applying [`RateLimiter`] to noisy-target events; `None`
/// (operator override) lets everything through.
struct NoisyTargetLimiter {
    limiter: Option<Arc<RateLimiter>>,
}

impl<S: Subscriber> Filter<S> for NoisyTargetLimiter {
    fn enabled(&self, _: &Metadata<'_>, _: &Context<'_, S>) -> bool {
        true
    }

    fn event_enabled(&self, event: &Event<'_>, _: &Context<'_, S>) -> bool {
        match &self.limiter {
            Some(limiter) if is_noisy_target(event.metadata().target()) => {
                limiter.admit(Instant::now())
            }
            _ => true,
        }
    }
}

/// Install the global subscriber from `RUST_LOG`, with the same
/// `RUST_LOG` semantics as before plus the noisy-target rate limit.
pub fn init() {
    let raw = std::env::var("RUST_LOG").ok();
    let setup = LogSetup::resolve(raw.as_deref());
    let env = EnvFilter::try_new(&setup.filter_spec).unwrap_or_else(|_| EnvFilter::new("info"));
    let limiter = build_limiter(setup.rate_limit, |l| {
        spawn_summary_ticker(l, SUMMARY_TICK, emit_summary)
    });
    let layer =
        tracing_subscriber::fmt::layer().with_filter(env.and(NoisyTargetLimiter { limiter }));
    tracing_subscriber::registry().with(layer).init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn override_matrix_only_explicit_trace_debug_directives_disable_the_limiter() {
        for spec in [
            // trace/debug (or numeric 5/4) on the target or any string prefix
            "hickory_proto=trace",
            "hickory_proto=debug",
            "hickory_proto=DEBUG",
            "hickory_proto=5",
            "hickory_proto=4",
            "hickory_proto::dnssec=trace",
            "hickory_proto::dnssec::dnssec_dns_handle=debug",
            "hickory_proto::xfer::dnssec_dns_handle=debug",
            // EnvFilter matches targets by plain string prefix
            "hickory=debug",
            "hickory_p=trace",
            // no level means trace
            "hickory_proto",
            "info,hickory_proto=debug",
            " info , hickory_proto::dnssec=debug ",
            // commas inside span/field filters must not confuse the parse
            "info,foo[span{a=1,b=2}]=debug,hickory_proto=debug",
            // the most specific explicit directive wins
            "warn,hickory_proto=debug",
            "info,hickory_proto::dnssec=debug,hickory_proto=warn",
        ] {
            assert!(names_noisy_target(spec), "{spec} must disable the limiter");
        }
        for spec in [
            // a bare global level does NOT disable it: debugging everything
            // must not bring back the 4k/s flood from this one target
            "debug",
            "trace",
            "5",
            "TRACE",
            "warn,debug",
            "debug,algod_rust=info",
            // info is the default and the flood is ERROR: the limiter stays on
            "hickory_proto=info",
            "hickory_proto=INFO",
            "hickory_proto=3",
            "hickory_proto::dnssec::dnssec_dns_handle=info",
            // quieting directives keep the limiter
            "hickory_proto=warn",
            "hickory_proto=error",
            "hickory_proto=off",
            "hickory_proto=1",
            " info , hickory_proto::dnssec=warn ",
            // the more specific directive beats a verbose less specific one
            "hickory_proto=debug,hickory_proto::dnssec=error",
            "debug,hickory_proto=info",
            // non-verbose globals
            "info",
            "warn",
            "off",
            "3",
            // unrelated targets
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

    /// Whether one event (error or info level) passes `filter`.
    fn passes(filter: EnvFilter, level_error: bool) -> bool {
        let seen = Arc::new(AtomicUsize::new(0));
        let sub = tracing_subscriber::registry().with(Count(seen.clone()).with_filter(filter));
        tracing::subscriber::with_default(sub, || {
            if level_error {
                tracing::error!(target: "x", "e");
            } else {
                tracing::info!(target: "x", "i");
            }
        });
        seen.load(Ordering::SeqCst) == 1
    }

    #[test]
    fn unset_rust_log_gets_info_and_the_policy() {
        let s = LogSetup::resolve(None);
        assert_eq!(s.filter_spec, "info");
        assert!(s.rate_limit);
    }

    #[test]
    fn explicit_filter_is_kept_and_override_disables_limit() {
        let s = LogSetup::resolve(Some("warn"));
        assert_eq!(s.filter_spec, "warn");
        assert!(s.rate_limit);
        let s = LogSetup::resolve(Some("info,hickory_proto=trace"));
        assert_eq!(s.filter_spec, "info,hickory_proto=trace");
        assert!(!s.rate_limit);
        let s = LogSetup::resolve(Some("debug"));
        assert!(s.rate_limit, "global debug keeps the limiter");
        let s = LogSetup::resolve(Some("hickory=debug"));
        assert!(!s.rate_limit);
    }

    /// Blank and invalid `RUST_LOG` behave exactly as the previous
    /// initializer (`EnvFilter::try_from_default_env()`, falling back to
    /// `info`), checked against that very call.
    #[test]
    fn blank_and_invalid_rust_log_behave_as_before() {
        fn old_filter() -> EnvFilter {
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
        }
        // Only this test touches RUST_LOG.
        let saved = std::env::var("RUST_LOG").ok();
        for raw in ["", "   ", "info,foo[bar=trace", "==="] {
            std::env::set_var("RUST_LOG", raw);
            let setup = LogSetup::resolve(Some(raw));
            let new =
                EnvFilter::try_new(&setup.filter_spec).unwrap_or_else(|_| EnvFilter::new("info"));
            let old = old_filter();
            for level_error in [false, true] {
                let o = passes(old_filter(), level_error);
                let n = passes(
                    EnvFilter::try_new(&setup.filter_spec)
                        .unwrap_or_else(|_| EnvFilter::new("info")),
                    level_error,
                );
                assert_eq!(n, o, "RUST_LOG={raw:?} error={level_error}");
            }
            assert_eq!(new.to_string(), old.to_string(), "RUST_LOG={raw:?}");
        }
        match saved {
            Some(v) => std::env::set_var("RUST_LOG", v),
            None => std::env::remove_var("RUST_LOG"),
        }
        // Invalid falls back silently to info with the policy applied.
        let s = LogSetup::resolve(Some("info,foo[bar=trace"));
        assert_eq!(s.filter_spec, "info");
        assert!(s.rate_limit);
    }

    // The limiter is driven by explicit instants (a fake clock): no real
    // time is involved in these tests.

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
        assert_eq!(l.flush(t0 + w - Duration::from_secs(1)), None);
        assert_eq!(l.flush(t0 + w + Duration::from_secs(1)), Some(10));
        assert_eq!(l.flush(t0 + w + Duration::from_secs(2)), None);
        let quiet = RateLimiter::new(5, w);
        quiet.admit(t0);
        assert_eq!(quiet.flush(t0 + w + Duration::from_secs(1)), None);
    }

    /// Under a continuous flood each window's drops are reported on their
    /// own, right after that window ends.
    #[test]
    fn continuous_flood_reports_each_window_separately_and_promptly() {
        let t0 = Instant::now();
        let w = Duration::from_secs(60);
        let l = RateLimiter::new(5, w);
        let mut reports = Vec::new();
        for sec in 0..130u64 {
            let now = t0 + Duration::from_secs(sec);
            l.admit(now);
            if let Some(n) = l.flush(now) {
                reports.push((sec, n));
            }
        }
        assert_eq!(reports, vec![(60, 55), (120, 55)]);
    }

    #[test]
    fn drops_of_an_unflushed_window_are_not_lost() {
        let t0 = Instant::now();
        let w = Duration::from_secs(60);
        let l = RateLimiter::new(1, w);
        l.admit(t0);
        l.admit(t0); // dropped
        assert!(l.admit(t0 + w + Duration::from_secs(1)));
        assert_eq!(l.flush(t0 + w * 3), Some(1));
    }

    /// Real-thread smoke test: only that a summary is eventually emitted
    /// (no exact counts or timings; those are covered with the fake clock).
    #[test]
    fn ticker_smoke_eventually_emits_a_summary() {
        let l = Arc::new(RateLimiter::new(2, Duration::from_millis(50)));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        spawn_summary_ticker(&l, Duration::from_millis(10), move |n| {
            sink.lock().unwrap().push(n)
        })
        .expect("spawn ticker");
        for _ in 0..10 {
            l.admit(Instant::now());
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while seen.lock().unwrap().is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!seen.lock().unwrap().is_empty(), "a summary was emitted");
    }

    /// The summary is an error-volume notice: it must survive a filter that
    /// only lets ERROR through (`RUST_LOG=error`, `hickory_proto=error`).
    #[test]
    fn summary_passes_an_error_only_filter() {
        let seen = Arc::new(AtomicUsize::new(0));
        let sub = tracing_subscriber::registry()
            .with(Count(seen.clone()).with_filter(EnvFilter::new("error")));
        tracing::subscriber::with_default(sub, || emit_summary(42));
        assert_eq!(seen.load(Ordering::SeqCst), 1);
    }

    /// If the summary thread cannot start, the limiter is not installed at
    /// all (otherwise events would be dropped with no summary ever).
    #[test]
    fn spawn_failure_means_no_limiter() {
        let fail = |_: &Arc<RateLimiter>| Err(std::io::Error::other("no threads"));
        assert!(build_limiter(true, fail).is_none());
        let ok = |_: &Arc<RateLimiter>| Ok(());
        assert!(build_limiter(true, ok).is_some());
        let never = |_: &Arc<RateLimiter>| -> std::io::Result<()> {
            panic!("must not spawn when the limiter is off")
        };
        assert!(build_limiter(false, never).is_none());
    }

    /// Counts events reaching it.
    struct Count(Arc<AtomicUsize>);
    impl<S: Subscriber> Layer<S> for Count {
        fn on_event(&self, _: &Event<'_>, _: Context<'_, S>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn count_events(limiter: Option<Arc<RateLimiter>>) -> usize {
        let seen = Arc::new(AtomicUsize::new(0));
        let sub = tracing_subscriber::registry().with(
            Count(seen.clone())
                .with_filter(EnvFilter::new("info").and(NoisyTargetLimiter { limiter })),
        );
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
        seen.load(Ordering::SeqCst)
    }

    #[test]
    fn composed_filter_limits_only_the_noisy_target() {
        let limiter = Some(Arc::new(RateLimiter::new(2, Duration::from_secs(3600))));
        assert_eq!(count_events(limiter), 2 + 3);
        assert_eq!(count_events(None), 10 + 4 + 3);
    }
}
