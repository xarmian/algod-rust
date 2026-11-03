// Copyright (c) 2026 Algod DAO
//
// SPDX-License-Identifier: MIT
// For the full license text, see LICENSE-MIT at the repository root.

//! One overall shutdown deadline for a node's teardown (issue #2138).
//!
//! go-algorand's `AlgorandFullNode.Stop` waits on its services with no
//! deadline. A container runtime does not: `docker stop` sends SIGKILL after
//! its grace period (10 s by default), and a kill mid-teardown skips every
//! destructor (`algod.pid`, `algod-listen.net`, log flushing). This module
//! gives the teardown one budget instead: a [`Teardown`] runs named steps in
//! order, each bounded by what is left of the overall deadline, and records
//! which steps finished, overran (abandoned) or were skipped.
//!
//! # Policy
//!
//! - Every step is bounded: an async stop by `tokio::time::timeout`, a
//!   blocking join (`std::thread::JoinHandle::join` has no timeout) by
//!   [`join_thread`], which waits on the blocking pool, so an abandoned wait
//!   never stalls the async task.
//! - A step that overruns is abandoned: its thread keeps running and is
//!   logged. The process still exits, because `main` returns (running the
//!   destructors) and then drops the runtime with a short bound; plain
//!   threads do not hold a process open, and blocking-pool threads are
//!   abandoned by that bounded drop.
//! - [`StepKind::Critical`] steps stop the writers of durable state (the
//!   agreement service, the pool follower, the state-proof service). Each
//!   has a guaranteed minimum that earlier steps cannot spend, so a hung
//!   earlier step never starves them. [`StepKind::BestEffort`] steps (gossip
//!   close, REST drain, catchpoint-export wait) are safe to abandon: nothing
//!   they leave behind needs repair (exports are written atomically).
//!   The ledger itself has no flush step: every block commits in its own
//!   SQLite transaction, so stopping its writers is what protects it.

use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tracing::{info, warn};

/// Environment variable overriding [`DEFAULT_SHUTDOWN_DEADLINE`], in
/// seconds. An operator whose container runtime grants a longer grace period
/// (`docker stop -t 30`) can raise it.
pub const SHUTDOWN_DEADLINE_SECS_ENV: &str = "ALGOD_SHUTDOWN_DEADLINE_SECS";

/// Total time the process spends in the teardown steps. With `main`'s
/// runtime drop bound (`RUNTIME_SHUTDOWN_TIMEOUT`, 1 s) the worst case is
/// 9 s, inside `docker stop`'s default 10 s grace period.
pub const DEFAULT_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(8);

/// The `participate` teardown, in order, against [`DEFAULT_SHUTDOWN_DEADLINE`]
/// (8 s). `cap` is the most a step may take, `reserved` the time no earlier
/// step can spend.
///
/// | step | kind | cap | reserved |
/// |---|---|---|---|
/// | `live_catchup` | best effort | 5 s (`LIVE_CATCHUP_SHUTDOWN_TIMEOUT`) | |
/// | `agreement` | critical | 4 s | 1.5 s |
/// | `pool_follower` | critical | 2 s | 0.5 s |
/// | `participation_refresher` | best effort | 1 s | |
/// | `heartbeat_service` | best effort | 1 s | |
/// | `state_proof_service` | critical | 1 s | 0.5 s |
/// | `tx_syncer` | best effort | 1 s | |
/// | `gossip` | best effort | 2 s | |
/// | `rest_server` | best effort | 5 s (`REST_SHUTDOWN_HARD_CAP`) | |
/// | `catchpoint_export` | best effort | 30 s (`CATCHPOINT_EXPORT_SHUTDOWN_TIMEOUT`) | |
///
/// Everything is also limited by what is left of the 8 s, so the caps are
/// ceilings, not a sum: the worst case with every step hung is 8 s plus
/// `main`'s 1 s runtime drop. Normal shutdown takes well under a second
/// (nothing blocks, no export is pending). The critical steps are the
/// writers of durable state (agreement's crash state and ledger commits, the
/// pool follower, the state-proof builder), so they keep their reserved time
/// even if the live-catchup stop or any earlier step hangs; the best-effort
/// steps at the tail (REST drain, catchpoint export) are skipped once the
/// deadline is spent.
pub fn participate_plan() -> Vec<StepPlan> {
    let s = Duration::from_secs;
    let ms = Duration::from_millis;
    vec![
        StepPlan::best_effort("live_catchup", s(5)),
        StepPlan::critical("agreement", s(4), ms(1500)),
        StepPlan::critical("pool_follower", s(2), ms(500)),
        StepPlan::best_effort("participation_refresher", s(1)),
        StepPlan::best_effort("heartbeat_service", s(1)),
        StepPlan::critical("state_proof_service", s(1), ms(500)),
        StepPlan::best_effort("tx_syncer", s(1)),
        StepPlan::best_effort("gossip", s(2)),
        StepPlan::best_effort("rest_server", s(5)),
        StepPlan::best_effort("catchpoint_export", s(30)),
    ]
}

/// Whether a step may be abandoned without risking durable state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepKind {
    /// Stops a writer of durable state: its `guaranteed` time is reserved.
    Critical,
    /// Safe to abandon; skipped once the deadline is spent.
    BestEffort,
}

/// One planned teardown step.
#[derive(Clone, Copy, Debug)]
pub struct StepPlan {
    pub name: &'static str,
    pub kind: StepKind,
    /// Longest this step may take, deadline permitting.
    pub cap: Duration,
    /// Time reserved for this step against every earlier step.
    pub guaranteed: Duration,
}

impl StepPlan {
    pub const fn critical(name: &'static str, cap: Duration, guaranteed: Duration) -> Self {
        Self {
            name,
            kind: StepKind::Critical,
            cap,
            guaranteed,
        }
    }

    pub const fn best_effort(name: &'static str, cap: Duration) -> Self {
        Self {
            name,
            kind: StepKind::BestEffort,
            cap,
            guaranteed: Duration::ZERO,
        }
    }
}

/// How one step ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepStatus {
    Ok,
    /// Overran its budget and was abandoned.
    TimedOut,
    /// Had no time left when its turn came.
    Skipped,
}

/// The end-of-shutdown report.
#[derive(Clone, Debug)]
pub struct Summary {
    pub steps: Vec<(&'static str, StepStatus)>,
    pub elapsed: Duration,
}

impl Summary {
    fn names(&self, status: StepStatus) -> Vec<&'static str> {
        self.steps
            .iter()
            .filter(|(_, s)| *s == status)
            .map(|(n, _)| *n)
            .collect()
    }

    pub fn timed_out(&self) -> Vec<&'static str> {
        self.names(StepStatus::TimedOut)
    }

    pub fn skipped(&self) -> Vec<&'static str> {
        self.names(StepStatus::Skipped)
    }

    pub fn ok_count(&self) -> usize {
        self.names(StepStatus::Ok).len()
    }

    /// `shutdown: 7 steps ok in 123 ms; timed out: [a]; skipped: [b]`
    pub fn line(&self) -> String {
        format!(
            "shutdown: {} steps ok in {} ms; timed out: {:?}; skipped: {:?}",
            self.ok_count(),
            self.elapsed.as_millis(),
            self.timed_out(),
            self.skipped()
        )
    }
}

/// Work abandoned by a timed-out step, for `main`'s exit log (issue #2142).
static ABANDONED: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());

/// Names of the steps abandoned so far in this process.
pub fn abandoned_steps() -> Vec<&'static str> {
    ABANDONED.lock().map(|g| g.clone()).unwrap_or_default()
}

/// Runs named steps against one overall deadline.
pub struct Teardown {
    start: Instant,
    deadline: Instant,
    plan: Vec<StepPlan>,
    done: Vec<(&'static str, StepStatus)>,
}

impl Teardown {
    pub fn new(total: Duration, plan: Vec<StepPlan>) -> Self {
        let start = Instant::now();
        Self {
            start,
            deadline: start + total,
            plan,
            done: Vec::new(),
        }
    }

    /// The time `name` may take right now: its cap, limited by what is left
    /// of the deadline after the time reserved for the later critical steps.
    pub fn budget(&self, name: &str) -> Duration {
        let Some(idx) = self.plan.iter().position(|p| p.name == name) else {
            return Duration::ZERO;
        };
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        let reserved_later: Duration = self.plan[idx + 1..].iter().map(|p| p.guaranteed).sum();
        let plan = &self.plan[idx];
        let available = remaining.saturating_sub(reserved_later);
        let mut budget = plan.cap.min(available);
        if plan.kind == StepKind::Critical {
            budget = budget.max(plan.guaranteed.min(remaining).min(plan.cap));
        }
        budget
    }

    /// Run step `name` with its budget. `f` receives the budget (for a callee
    /// with its own timeout argument). Returns the step's result, or `None`
    /// when it timed out or was skipped.
    pub async fn run<T, F, Fut>(&mut self, name: &'static str, f: F) -> Option<T>
    where
        F: FnOnce(Duration) -> Fut,
        Fut: Future<Output = T>,
    {
        let budget = self.budget(name);
        let kind = self
            .plan
            .iter()
            .find(|p| p.name == name)
            .map(|p| p.kind)
            .unwrap_or(StepKind::BestEffort);
        if budget.is_zero() && kind == StepKind::BestEffort {
            warn!(step = name, "shutdown: no time left, skipping step");
            self.record(name, StepStatus::Skipped);
            return None;
        }
        match tokio::time::timeout(budget, f(budget)).await {
            Ok(v) => {
                self.record(name, StepStatus::Ok);
                Some(v)
            }
            Err(_) => {
                warn!(step = name, budget = ?budget, "shutdown: step overran its budget, abandoning it");
                self.record(name, StepStatus::TimedOut);
                None
            }
        }
    }

    /// Record a step that was not run for a reason of the caller's.
    pub fn skip(&mut self, name: &'static str, why: &str) {
        warn!(step = name, why, "shutdown: skipping step");
        self.record(name, StepStatus::Skipped);
    }

    fn record(&mut self, name: &'static str, status: StepStatus) {
        if status != StepStatus::Ok {
            if let Ok(mut g) = ABANDONED.lock() {
                g.push(name);
            }
        }
        self.done.push((name, status));
    }

    /// Log the one-line summary and return it.
    pub fn finish(self) -> Summary {
        let summary = Summary {
            steps: self.done,
            elapsed: self.start.elapsed(),
        };
        if summary.timed_out().is_empty() && summary.skipped().is_empty() {
            info!("{}", summary.line());
        } else {
            warn!("{}", summary.line());
        }
        summary
    }
}

/// Join a thread without blocking the async task: the blocking join runs on
/// the blocking pool, so a timeout drops the wait and leaves the thread (and
/// its pool slot) to the bounded runtime drop at exit.
pub async fn join_thread<T: Send + 'static>(handle: std::thread::JoinHandle<T>) {
    let _ = tokio::task::spawn_blocking(move || {
        let _ = handle.join();
    })
    .await;
}

/// Run a blocking closure on the blocking pool (a destructor that joins).
pub async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    tokio::task::spawn_blocking(f).await.ok()
}

/// The configured overall deadline: [`SHUTDOWN_DEADLINE_SECS_ENV`] when it
/// parses to a positive number of seconds, else the default.
pub fn deadline_from(env_value: Option<&str>) -> Duration {
    env_value
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|s| *s > 0)
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_SHUTDOWN_DEADLINE)
}

/// Log, at `main`'s exit, the work that was abandoned and may still run.
pub fn log_abandoned_at_exit() {
    let abandoned = abandoned_steps();
    if !abandoned.is_empty() {
        warn!(
            steps = ?abandoned,
            "exiting with abandoned shutdown steps; blocking work still running is dropped with the process"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: fn(u64) -> Duration = Duration::from_millis;

    async fn hang() {
        // A step that never returns (a stub join on a stuck thread).
        std::future::pending::<()>().await
    }

    #[tokio::test]
    async fn several_hung_steps_still_finish_within_the_deadline() {
        let plan = vec![
            StepPlan::best_effort("a", MS(10_000)),
            StepPlan::critical("b", MS(10_000), MS(100)),
            StepPlan::best_effort("c", MS(10_000)),
            StepPlan::best_effort("d", MS(10_000)),
        ];
        let mut td = Teardown::new(MS(500), plan);
        let t = Instant::now();
        assert!(td.run("a", |_| hang()).await.is_none());
        assert!(td.run("b", |_| hang()).await.is_none());
        assert!(td.run("c", |_| hang()).await.is_none());
        assert!(td.run("d", |_| hang()).await.is_none());
        let s = td.finish();
        assert!(t.elapsed() < MS(500) + MS(250), "took {:?}", t.elapsed());
        assert!(s.elapsed < MS(750));
        assert_eq!(s.ok_count(), 0);
    }

    #[tokio::test]
    async fn a_critical_step_runs_after_earlier_steps_hang() {
        let plan = vec![
            StepPlan::best_effort("hung1", MS(10_000)),
            StepPlan::best_effort("hung2", MS(10_000)),
            StepPlan::critical("data", MS(10_000), MS(200)),
            StepPlan::best_effort("late", MS(10_000)),
        ];
        let mut td = Teardown::new(MS(600), plan);
        assert!(td.run("hung1", |_| hang()).await.is_none());
        assert!(td.run("hung2", |_| hang()).await.is_none());
        // `hung1` could use at most 600 - 200 ms, so `data` still has its own.
        assert!(td.budget("data") >= MS(150), "{:?}", td.budget("data"));
        let ran = td.run("data", |_| async { 7 }).await;
        assert_eq!(ran, Some(7));
        let s = td.finish();
        assert!(s.steps.contains(&("data", StepStatus::Ok)));
    }

    #[tokio::test]
    async fn a_best_effort_step_is_skipped_once_the_deadline_is_spent() {
        let plan = vec![
            StepPlan::best_effort("slow", MS(10_000)),
            StepPlan::best_effort("export", MS(30_000)),
        ];
        let mut td = Teardown::new(MS(200), plan);
        assert!(td.run("slow", |_| hang()).await.is_none());
        let t = Instant::now();
        assert!(td.run("export", |_| hang()).await.is_none());
        assert!(t.elapsed() < MS(50), "a skipped step must not wait");
        let s = td.finish();
        assert_eq!(s.timed_out(), vec!["slow"]);
        assert_eq!(s.skipped(), vec!["export"]);
    }

    #[tokio::test]
    async fn the_summary_line_lists_the_timed_out_steps() {
        let plan = vec![
            StepPlan::best_effort("gossip", MS(50)),
            StepPlan::best_effort("rest", MS(50)),
            StepPlan::best_effort("ok", MS(50)),
        ];
        let mut td = Teardown::new(MS(1_000), plan);
        td.run("gossip", |_| hang()).await;
        td.run("rest", |_| hang()).await;
        td.run("ok", |_| async {}).await;
        let s = td.finish();
        let line = s.line();
        assert!(line.starts_with("shutdown: 1 steps ok in "), "{line}");
        assert!(line.contains("timed out: [\"gossip\", \"rest\"]"), "{line}");
        assert!(line.contains("skipped: []"), "{line}");
    }

    #[tokio::test]
    async fn a_step_receives_its_budget() {
        let plan = vec![StepPlan::best_effort("catchup", MS(300))];
        let mut td = Teardown::new(MS(5_000), plan);
        let got = td.run("catchup", |b| async move { b }).await.unwrap();
        assert_eq!(got, MS(300));
        td.finish();
    }

    #[test]
    fn a_hung_thread_join_is_abandoned_and_the_runtime_still_exits() {
        // Runs on its own runtime so the bounded drop is the thing measured.
        let t = Instant::now();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        rt.block_on(async {
            let stuck = std::thread::spawn(move || {
                let _ = rx.recv_timeout(Duration::from_secs(20));
            });
            let mut td = Teardown::new(MS(300), vec![StepPlan::best_effort("join", MS(10_000))]);
            let r = td.run("join", |_| join_thread(stuck)).await;
            assert!(r.is_none());
            assert_eq!(td.finish().timed_out(), vec!["join"]);
        });
        rt.shutdown_timeout(MS(100));
        assert!(
            t.elapsed() < Duration::from_secs(3),
            "took {:?}",
            t.elapsed()
        );
        drop(tx);
    }

    #[tokio::test]
    async fn a_thread_that_finishes_is_joined() {
        let h = std::thread::spawn(|| std::thread::sleep(MS(20)));
        let mut td = Teardown::new(MS(2_000), vec![StepPlan::critical("j", MS(1_000), MS(10))]);
        assert!(td.run("j", |_| join_thread(h)).await.is_some());
        assert_eq!(td.finish().ok_count(), 1);
    }

    #[test]
    fn the_participate_plan_fits_the_default_deadline_and_a_docker_stop() {
        let plan = participate_plan();
        let reserved: Duration = plan.iter().map(|p| p.guaranteed).sum();
        assert!(reserved < DEFAULT_SHUTDOWN_DEADLINE);
        // The live-catchup cap still fits once the critical steps are reserved.
        assert!(plan[0].cap + reserved <= DEFAULT_SHUTDOWN_DEADLINE);
        // 8 s + main's 1 s runtime drop stays inside docker stop's 10 s.
        assert!(DEFAULT_SHUTDOWN_DEADLINE + Duration::from_secs(1) < Duration::from_secs(10));
        // Only writers of durable state are critical.
        let critical: Vec<_> = plan
            .iter()
            .filter(|p| p.kind == StepKind::Critical)
            .map(|p| p.name)
            .collect();
        assert_eq!(
            critical,
            ["agreement", "pool_follower", "state_proof_service"]
        );
    }

    #[tokio::test]
    async fn the_participate_plan_with_every_step_hung_ends_within_the_deadline() {
        // Scaled-down deadline, real plan shape: a hung catchup stop must not
        // starve the critical steps, and the tail is skipped.
        let plan: Vec<StepPlan> = participate_plan()
            .into_iter()
            .map(|p| StepPlan {
                cap: p.cap / 10,
                guaranteed: p.guaranteed / 10,
                ..p
            })
            .collect();
        let names: Vec<&'static str> = plan.iter().map(|p| p.name).collect();
        let mut td = Teardown::new(DEFAULT_SHUTDOWN_DEADLINE / 10, plan);
        let t = Instant::now();
        for n in &names {
            td.run(n, |_| hang()).await;
        }
        let s = td.finish();
        assert!(
            t.elapsed() < DEFAULT_SHUTDOWN_DEADLINE / 10 + MS(250),
            "{:?}",
            t.elapsed()
        );
        // Every critical step was attempted with a real budget (timed out,
        // not skipped), and the tail was skipped.
        for c in ["agreement", "pool_follower", "state_proof_service"] {
            assert!(
                s.steps.contains(&(c, StepStatus::TimedOut)),
                "{c}: {:?}",
                s.steps
            );
        }
        assert!(s.skipped().contains(&"catchpoint_export"), "{:?}", s.steps);
    }

    #[test]
    fn the_deadline_env_parses_positive_seconds_only() {
        assert_eq!(deadline_from(None), DEFAULT_SHUTDOWN_DEADLINE);
        assert_eq!(deadline_from(Some("20")), Duration::from_secs(20));
        assert_eq!(deadline_from(Some(" 3 ")), Duration::from_secs(3));
        assert_eq!(deadline_from(Some("0")), DEFAULT_SHUTDOWN_DEADLINE);
        assert_eq!(deadline_from(Some("abc")), DEFAULT_SHUTDOWN_DEADLINE);
    }
}
