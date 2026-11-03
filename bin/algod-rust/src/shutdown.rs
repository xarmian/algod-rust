// Copyright (c) 2026 Algod DAO
//
// SPDX-License-Identifier: MIT
// For the full license text, see LICENSE-MIT at the repository root.

//! One overall shutdown deadline for a node's teardown (issue #2138), and the
//! process-wide shutdown request (issue #2195).
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
//!   [`join_thread`], which joins on a detached helper thread.
//! - A step that overruns is abandoned: its thread keeps running and is
//!   logged. The process still exits, because `main` returns (running the
//!   destructors) and then drops the runtime with a short bound; plain
//!   threads do not hold a process open.
//! - [`StepKind::Critical`] steps stop the writers of durable state (the
//!   agreement service, the pool follower, the state-proof service). Each
//!   has a guaranteed minimum that earlier steps cannot spend, so a hung
//!   earlier step never starves them, and even with nothing left they get a
//!   short floor ([`CRITICAL_FLOOR`]) to run instant stops. [`StepKind::BestEffort`]
//!   steps (gossip close, REST drain, catchpoint-export wait) are safe to
//!   abandon: nothing they leave behind needs repair (exports are written
//!   atomically). The ledger itself has no flush step: every block commits in
//!   its own SQLite transaction, so stopping its writers is what protects it.
//! - Independent steps (thread joins whose stop flags are already set) run
//!   concurrently under [`Teardown::run_group`], so one hung join does not
//!   eat the time of the others.
//! - A value whose destructor can block (a handle that joins on drop) must
//!   be handed to [`join_thread`] / [`drop_in_thread`] BEFORE the step is
//!   built: those start a detached thread at once, so a step that is later
//!   skipped can never run the destructor on the async task.

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tracing::{info, warn};

/// Environment variable overriding [`DEFAULT_SHUTDOWN_DEADLINE`], in
/// seconds. An operator whose container runtime grants a longer grace period
/// (`docker stop -t 30`) can raise it.
pub const SHUTDOWN_DEADLINE_SECS_ENV: &str = "ALGOD_SHUTDOWN_DEADLINE_SECS";

/// Total time the process spends in the teardown steps.
///
/// Budget against `docker stop`'s default 10 s grace period: this deadline,
/// plus the work after the last step ([`EXIT_WORK_ALLOWANCE`]: the
/// destructors of `participate`'s locals, the SQLite handles, the pid file,
/// measured at a few milliseconds), plus the bounded runtime drop
/// ([`RUNTIME_DROP_BOUND`]) stays within [`TOTAL_EXIT_BUDGET`], 9 s.
pub const DEFAULT_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(7);

/// Allowance for everything between the last teardown step and the runtime
/// drop (destructors, log flush). Measured, see `log_exit_timing`.
pub const EXIT_WORK_ALLOWANCE: Duration = Duration::from_secs(1);

/// How long `main`'s runtime drop waits for tokio blocking work still running.
/// Only real `spawn_blocking` stragglers can reach it: teardown joins run on
/// detached std threads, which do not hold the runtime open.
pub const RUNTIME_DROP_BOUND: Duration = Duration::from_secs(1);

/// The most the process may spend from the shutdown request to exit, a margin
/// inside `docker stop`'s 10 s.
pub const TOTAL_EXIT_BUDGET: Duration = Duration::from_secs(9);

// The exit budget is a compile-time invariant, not just a test.
const _: () = assert!(
    DEFAULT_SHUTDOWN_DEADLINE.as_millis()
        + EXIT_WORK_ALLOWANCE.as_millis()
        + RUNTIME_DROP_BOUND.as_millis()
        <= TOTAL_EXIT_BUDGET.as_millis()
);

/// Time a critical step always gets, even past the deadline, so an instant
/// stop (set a flag, drop a handle) is never cancelled before it runs.
pub const CRITICAL_FLOOR: Duration = Duration::from_millis(100);

/// A best-effort step with less than this left is skipped, not started.
const MIN_USEFUL_BUDGET: Duration = Duration::from_millis(10);

/// The `participate` teardown, in order, against [`DEFAULT_SHUTDOWN_DEADLINE`]
/// (7 s). `cap` is the most a step may take, `reserved` the time no earlier
/// step can spend. `state_proof` says whether the state-proof service runs
/// (a step that will not run reserves nothing).
///
/// | step | kind | cap | reserved |
/// |---|---|---|---|
/// | `live_catchup` | best effort | 5 s (`LIVE_CATCHUP_SHUTDOWN_TIMEOUT`) | |
/// | `agreement` | critical | 4 s | 1.5 s |
/// | group `joins`: `pool_follower` | critical | 2 s | 0.5 s (the group's) |
/// | group `joins`: `state_proof_service` (if running) | critical | 1 s | in the group's 0.5 s |
/// | group `joins`: `participation_refresher`, `heartbeat_service` | best effort | 1 s | |
/// | `tx_syncer` | best effort | 1 s | |
/// | `gossip` | best effort | 2 s | |
/// | `rest_server` | best effort | 5 s (`REST_SHUTDOWN_HARD_CAP`) | |
/// | `catchpoint_export` | best effort | 30 s (`CATCHPOINT_EXPORT_SHUTDOWN_TIMEOUT`) | |
///
/// Everything is also limited by what is left of the 7 s, so the caps are
/// ceilings, not a sum: the worst case with every step hung is the deadline
/// itself (plus [`CRITICAL_FLOOR`] per critical step only if a reservation
/// were ever exhausted, which the reservations prevent). Normal shutdown
/// takes well under a second (nothing blocks, no export is pending). The
/// critical steps are the writers of durable state (agreement's crash state
/// and ledger commits, the pool follower, the state-proof builder), so they
/// keep their reserved time even if the live-catchup stop or any earlier step
/// hangs; the best-effort steps at the tail (REST drain, catchpoint export)
/// are skipped once the deadline is spent. The reserve is 2 s, so the 5 s
/// live-catchup cap fits in full.
pub fn participate_plan(state_proof: bool) -> Vec<StepPlan> {
    let s = Duration::from_secs;
    let ms = Duration::from_millis;
    let mut plan = vec![
        StepPlan::best_effort("live_catchup", s(5)),
        StepPlan::critical("agreement", s(4), ms(1500)),
        StepPlan::critical("pool_follower", s(2), ms(500)).in_group("joins"),
    ];
    if state_proof {
        plan.push(StepPlan::critical("state_proof_service", s(1), ms(500)).in_group("joins"));
    }
    plan.extend([
        StepPlan::best_effort("participation_refresher", s(1)).in_group("joins"),
        StepPlan::best_effort("heartbeat_service", s(1)).in_group("joins"),
        StepPlan::best_effort("tx_syncer", s(1)),
        StepPlan::best_effort("gossip", s(2)),
        StepPlan::best_effort("rest_server", s(5)),
        StepPlan::best_effort("catchpoint_export", s(30)),
    ]);
    plan
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
    /// Steps of one group run concurrently; the group reserves the largest
    /// `guaranteed` of its members once, not their sum.
    pub group: Option<&'static str>,
}

impl StepPlan {
    pub const fn critical(name: &'static str, cap: Duration, guaranteed: Duration) -> Self {
        Self {
            name,
            kind: StepKind::Critical,
            cap,
            guaranteed,
            group: None,
        }
    }

    pub const fn best_effort(name: &'static str, cap: Duration) -> Self {
        Self {
            name,
            kind: StepKind::BestEffort,
            cap,
            guaranteed: Duration::ZERO,
            group: None,
        }
    }

    pub const fn in_group(mut self, group: &'static str) -> Self {
        self.group = Some(group);
        self
    }
}

/// How one step ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepStatus {
    Ok,
    /// Started, overran its budget and was abandoned (its work may still run).
    TimedOut,
    /// Never started: no time was left when its turn came.
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

    /// The exit-time warning for work that may still be running: only steps
    /// that started and overran. Skipped steps never ran, so nothing of
    /// theirs is abandoned (they are in [`Self::line`]).
    pub fn abandoned_line(&self) -> Option<String> {
        let abandoned = self.timed_out();
        if abandoned.is_empty() {
            None
        } else {
            Some(format!(
                "exiting with abandoned shutdown steps {abandoned:?}; their blocking work, if still running, is dropped with the process"
            ))
        }
    }
}

/// The report of the process's teardown, set by [`Teardown::finish_and_publish`]
/// for `main`'s exit log (issue #2142). Unit tests use [`Teardown::finish`],
/// which never touches it.
static PUBLISHED: Mutex<Option<Summary>> = Mutex::new(None);

/// Set when the last teardown step is done, to time the exit work after it.
static TEARDOWN_END: OnceLock<Instant> = OnceLock::new();

/// Log, at `main`'s exit, the work that was abandoned and may still run.
pub fn log_abandoned_at_exit() {
    let line = PUBLISHED
        .lock()
        .ok()
        .and_then(|g| g.as_ref().and_then(Summary::abandoned_line));
    if let Some(line) = line {
        warn!("{line}");
    }
}

/// Log how long the process has taken since the last teardown step, at a
/// named exit stage (after `run` returned its locals' destructors, after the
/// runtime drop). This is the measurement behind [`EXIT_WORK_ALLOWANCE`].
pub fn log_exit_timing(stage: &str) {
    if let Some(end) = TEARDOWN_END.get() {
        info!(
            stage,
            since_teardown_ms = end.elapsed().as_millis() as u64,
            "exit timing"
        );
    }
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

    /// Time reserved for the steps after `idx`, that are not in `idx`'s own
    /// group: ungrouped steps add up, a later group counts its largest member.
    fn reserved_after(&self, idx: usize) -> Duration {
        let own = self.plan[idx].group;
        let mut total = Duration::ZERO;
        let mut groups: Vec<(&'static str, Duration)> = Vec::new();
        for p in &self.plan[idx + 1..] {
            match p.group {
                Some(g) if Some(g) == own => {}
                Some(g) => match groups.iter_mut().find(|(n, _)| *n == g) {
                    Some((_, m)) => *m = (*m).max(p.guaranteed),
                    None => groups.push((g, p.guaranteed)),
                },
                None => total += p.guaranteed,
            }
        }
        total + groups.iter().map(|(_, m)| *m).sum::<Duration>()
    }

    /// The time `name` may take right now: its cap, limited by what is left
    /// of the deadline after the time reserved for the later critical steps;
    /// a critical step never gets less than [`CRITICAL_FLOOR`] (or its cap).
    pub fn budget(&self, name: &str) -> Duration {
        let Some(idx) = self.plan.iter().position(|p| p.name == name) else {
            return Duration::ZERO;
        };
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        let available = remaining.saturating_sub(self.reserved_after(idx));
        let plan = &self.plan[idx];
        let budget = plan.cap.min(available);
        match plan.kind {
            StepKind::Critical => budget.max(CRITICAL_FLOOR.min(plan.cap)),
            StepKind::BestEffort => budget,
        }
    }

    fn kind_of(&self, name: &str) -> StepKind {
        self.plan
            .iter()
            .find(|p| p.name == name)
            .map(|p| p.kind)
            .unwrap_or(StepKind::BestEffort)
    }

    fn is_skipped(&self, name: &str, budget: Duration) -> bool {
        self.kind_of(name) == StepKind::BestEffort && budget < MIN_USEFUL_BUDGET
    }

    /// Run step `name` with its budget. `f` receives the budget (for a callee
    /// with its own timeout argument). Returns the step's result, or `None`
    /// when it timed out or was skipped. `f` and what it captured is dropped
    /// inline when the step is skipped: never capture a value with a blocking
    /// destructor, pass [`join_thread`]/[`drop_in_thread`] futures built
    /// beforehand.
    pub async fn run<T, F, Fut>(&mut self, name: &'static str, f: F) -> Option<T>
    where
        F: FnOnce(Duration) -> Fut,
        Fut: Future<Output = T>,
    {
        let budget = self.budget(name);
        if self.is_skipped(name, budget) {
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

    /// Run independent steps concurrently, each with its own budget (all
    /// computed at the start, so a hung one costs the others nothing), and
    /// record them in the given order. The futures own everything they need.
    pub async fn run_group<Fut>(&mut self, steps: Vec<(&'static str, Fut)>)
    where
        Fut: Future<Output = ()> + Send + 'static,
    {
        let budgets: Vec<Duration> = steps.iter().map(|(n, _)| self.budget(n)).collect();
        let mut status: Vec<Option<StepStatus>> = vec![None; steps.len()];
        let mut names = Vec::with_capacity(steps.len());
        let mut set = tokio::task::JoinSet::new();
        for (i, (name, fut)) in steps.into_iter().enumerate() {
            names.push(name);
            if self.is_skipped(name, budgets[i]) {
                warn!(step = name, "shutdown: no time left, skipping step");
                status[i] = Some(StepStatus::Skipped);
                continue;
            }
            let budget = budgets[i];
            set.spawn(async move { (i, tokio::time::timeout(budget, fut).await.is_ok()) });
        }
        while let Some(joined) = set.join_next().await {
            if let Ok((i, ok)) = joined {
                if !ok {
                    warn!(step = names[i], budget = ?budgets[i], "shutdown: step overran its budget, abandoning it");
                }
                status[i] = Some(if ok {
                    StepStatus::Ok
                } else {
                    StepStatus::TimedOut
                });
            }
        }
        for (i, name) in names.into_iter().enumerate() {
            // A panicked step task never reported: it did not finish cleanly.
            self.record(name, status[i].unwrap_or(StepStatus::TimedOut));
        }
    }

    /// Record a step that was not run for a reason of the caller's.
    pub fn skip(&mut self, name: &'static str, why: &str) {
        warn!(step = name, why, "shutdown: skipping step");
        self.record(name, StepStatus::Skipped);
    }

    fn record(&mut self, name: &'static str, status: StepStatus) {
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

    /// [`Self::finish`], and keep the report for `main`'s exit log and mark
    /// the end of the teardown for the exit timing.
    pub fn finish_and_publish(self) -> Summary {
        let summary = self.finish();
        let _ = TEARDOWN_END.set(Instant::now());
        if let Ok(mut g) = PUBLISHED.lock() {
            *g = Some(summary.clone());
        }
        summary
    }
}

/// Join a thread without blocking the async task: a detached helper thread
/// joins it at once (not on first poll), so dropping the returned future, on a
/// timeout or because its step was skipped, never joins on the async task and
/// holds no tokio blocking-pool slot. A stuck thread is simply abandoned.
pub fn join_thread<T: Send + 'static>(
    handle: std::thread::JoinHandle<T>,
) -> impl Future<Output = ()> + Send + 'static {
    drop_in_thread(move || {
        let _ = handle.join();
    })
}

/// Run `work` (a destructor that joins, say) on a detached helper thread
/// started now; the future completes when it is done.
pub fn drop_in_thread<W: FnOnce() + Send + 'static>(
    work: W,
) -> impl Future<Output = ()> + Send + 'static {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let spawned = std::thread::Builder::new()
        .name("shutdown-helper".into())
        .spawn(move || {
            work();
            let _ = tx.send(());
        });
    if spawned.is_err() {
        warn!("shutdown: could not start a helper thread");
    }
    async move {
        let _ = rx.await;
    }
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

// ---------------------------------------------------------------------------
// The process-wide shutdown request (issue #2195)
// ---------------------------------------------------------------------------

/// How long, once a shutdown is requested while the node is still starting,
/// startup may take to reach the shutdown wait before the process cleans up
/// and exits on its own.
pub const STARTUP_GRACE: Duration = Duration::from_secs(2);

type Cleanup = Box<dyn FnOnce() + Send>;

/// A shutdown request (SIGTERM or SIGINT) that every waiter sees, however
/// early it came. Registered before the node starts (so the signal never hits
/// the default kill disposition, which left a stale `algod.pid`, issue
/// #2195); a request that arrives while startup is still running is not
/// swallowed: if startup does not reach [`Self::wait`] within
/// [`STARTUP_GRACE`] the process runs the registered cleanups and exits with
/// `128 + signal`, otherwise the normal bounded teardown takes over.
pub struct ShutdownSignal {
    requested: AtomicBool,
    code: AtomicI32,
    waiting: AtomicBool,
    tx: tokio::sync::watch::Sender<bool>,
    cleanups: Mutex<Vec<Cleanup>>,
    grace: Duration,
    exit: Box<dyn Fn(i32) + Send + Sync>,
}

static GLOBAL: OnceLock<Arc<ShutdownSignal>> = OnceLock::new();

impl ShutdownSignal {
    /// A signal with a custom grace and exit hook (tests).
    pub fn with_exit(grace: Duration, exit: impl Fn(i32) + Send + Sync + 'static) -> Arc<Self> {
        let (tx, _) = tokio::sync::watch::channel(false);
        Arc::new(Self {
            requested: AtomicBool::new(false),
            code: AtomicI32::new(0),
            waiting: AtomicBool::new(false),
            tx,
            cleanups: Mutex::new(Vec::new()),
            grace,
            exit: Box::new(exit),
        })
    }

    /// The process-wide signal, installing the OS handlers on first use.
    /// Idempotent; must run inside the runtime (the listener is a task). The
    /// handlers are registered before this returns, so no signal after it is
    /// lost.
    pub fn install_global() -> std::io::Result<Arc<Self>> {
        if let Some(g) = GLOBAL.get() {
            return Ok(Arc::clone(g));
        }
        let this = Self::with_exit(STARTUP_GRACE, |code| std::process::exit(code));
        this.spawn_listener()?;
        Ok(Arc::clone(GLOBAL.get_or_init(|| this)))
    }

    #[cfg(unix)]
    fn spawn_listener(self: &Arc<Self>) -> std::io::Result<()> {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate())?;
        let mut int = signal(SignalKind::interrupt())?;
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                let code = tokio::select! {
                    _ = term.recv() => 128 + 15,
                    _ = int.recv() => 128 + 2,
                };
                this.request(code);
            }
        });
        Ok(())
    }

    #[cfg(not(unix))]
    fn spawn_listener(self: &Arc<Self>) -> std::io::Result<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                if tokio::signal::ctrl_c().await.is_err() {
                    break;
                }
                this.request(128 + 2);
            }
        });
        Ok(())
    }

    /// Register work to run if the process has to exit during startup (remove
    /// the pid file). Runs at most once, on the watchdog thread.
    pub fn add_startup_cleanup(&self, f: impl FnOnce() + Send + 'static) {
        if let Ok(mut c) = self.cleanups.lock() {
            c.push(Box::new(f));
        }
    }

    /// Whether a shutdown was requested.
    #[cfg(test)]
    pub fn is_requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }

    /// Record a shutdown request. The first one wakes every waiter and, when
    /// nobody is waiting yet (the node is still starting), arms the startup
    /// watchdog on its own thread, so it fires even if the runtime is stuck.
    pub fn request(self: &Arc<Self>, code: i32) {
        if self.requested.swap(true, Ordering::SeqCst) {
            return;
        }
        self.code.store(code, Ordering::SeqCst);
        self.tx.send_replace(true);
        if self.waiting.load(Ordering::SeqCst) {
            return;
        }
        info!(code, "shutdown requested during startup");
        let this = Arc::clone(self);
        let _ = std::thread::Builder::new()
            .name("startup-watchdog".into())
            .spawn(move || this.watchdog());
    }

    fn watchdog(&self) {
        let deadline = Instant::now() + self.grace;
        while Instant::now() < deadline {
            if self.waiting.load(Ordering::SeqCst) {
                return; // startup finished: the normal bounded teardown runs
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if self.waiting.load(Ordering::SeqCst) {
            return;
        }
        warn!(
            grace = ?self.grace,
            "startup did not reach its shutdown wait after a shutdown request; cleaning up and exiting"
        );
        let cleanups = self
            .cleanups
            .lock()
            .map(|mut c| std::mem::take(&mut *c))
            .unwrap_or_default();
        for c in cleanups {
            c();
        }
        (self.exit)(self.code.load(Ordering::SeqCst));
    }

    /// Wait for a shutdown request (a request made earlier counts). Marks the
    /// node as having reached its shutdown wait, which hands a request made
    /// during startup over to the normal teardown.
    pub async fn wait(&self) {
        self.waiting.store(true, Ordering::SeqCst);
        let mut rx = self.tx.subscribe();
        let _ = rx.wait_for(|requested| *requested).await;
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

    struct SlowDrop(Arc<AtomicBool>);
    impl Drop for SlowDrop {
        fn drop(&mut self) {
            std::thread::sleep(Duration::from_secs(5));
            self.0.store(true, Ordering::SeqCst);
        }
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
    async fn a_critical_step_gets_a_floor_even_with_nothing_left() {
        // Nothing reserved for `stop`, and the earlier step spends everything.
        let plan = vec![
            StepPlan::best_effort("hog", MS(10_000)),
            StepPlan::critical("stop", MS(10_000), Duration::ZERO),
            StepPlan::critical("stuck", MS(10_000), Duration::ZERO),
        ];
        let mut td = Teardown::new(MS(150), plan);
        assert!(td.run("hog", |_| hang()).await.is_none());
        // The deadline is spent, yet an instant stop still runs to completion
        // (not recorded as timed out, not cancelled before its first poll).
        assert_eq!(td.run("stop", |_| async { 1 }).await, Some(1));
        let t = Instant::now();
        assert!(td.run("stuck", |_| hang()).await.is_none());
        assert!(
            t.elapsed() >= CRITICAL_FLOOR && t.elapsed() < CRITICAL_FLOOR + MS(200),
            "a hung critical step is cut off after the floor, took {:?}",
            t.elapsed()
        );
        let s = td.finish();
        assert!(s.steps.contains(&("stop", StepStatus::Ok)));
        assert!(s.steps.contains(&("stuck", StepStatus::TimedOut)));
        assert!(s.skipped().is_empty(), "{:?}", s.steps);
    }

    #[tokio::test]
    async fn a_skipped_step_never_counts_as_abandoned() {
        let plan = vec![
            StepPlan::best_effort("slow", MS(10_000)),
            StepPlan::best_effort("export", MS(30_000)),
        ];
        let mut td = Teardown::new(MS(100), plan);
        td.run("slow", |_| hang()).await;
        td.run("export", |_| hang()).await;
        let s = td.finish();
        let line = s.abandoned_line().expect("slow overran");
        assert!(line.contains("slow") && !line.contains("export"), "{line}");
        let all_skipped = Summary {
            steps: vec![("x", StepStatus::Skipped), ("y", StepStatus::Ok)],
            elapsed: MS(1),
        };
        assert!(all_skipped.abandoned_line().is_none());
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

    #[tokio::test]
    async fn a_group_runs_concurrently_one_hung_join_does_not_cost_the_others() {
        let (release, gate) = std::sync::mpsc::channel::<()>();
        let stuck = std::thread::spawn(move || {
            let _ = gate.recv_timeout(Duration::from_secs(20));
        });
        let quick1 = std::thread::spawn(|| std::thread::sleep(MS(20)));
        let quick2 = std::thread::spawn(|| std::thread::sleep(MS(20)));
        let plan = vec![
            StepPlan::critical("stuck", MS(400), MS(300)).in_group("g"),
            StepPlan::critical("quick1", MS(400), MS(300)).in_group("g"),
            StepPlan::best_effort("quick2", MS(400)).in_group("g"),
            StepPlan::best_effort("after", MS(400)),
        ];
        let mut td = Teardown::new(MS(2_000), plan);
        let t = Instant::now();
        td.run_group(vec![
            ("stuck", join_thread(stuck)),
            ("quick1", join_thread(quick1)),
            ("quick2", join_thread(quick2)),
        ])
        .await;
        // Concurrent: the group takes the hung step's budget once.
        assert!(t.elapsed() < MS(400) + MS(250), "took {:?}", t.elapsed());
        let s = td.finish();
        assert_eq!(s.timed_out(), vec!["stuck"]);
        assert!(s.steps.contains(&("quick1", StepStatus::Ok)));
        assert!(s.steps.contains(&("quick2", StepStatus::Ok)));
        drop(release);
    }

    #[test]
    fn a_group_reserves_its_largest_member_once_not_the_sum() {
        let plan = vec![
            StepPlan::best_effort("first", MS(10_000)),
            StepPlan::critical("a", MS(1_000), MS(500)).in_group("g"),
            StepPlan::critical("b", MS(1_000), MS(500)).in_group("g"),
        ];
        let td = Teardown::new(MS(2_000), plan);
        // 2000 ms minus the group's single 500 ms, not 1000.
        let b = td.budget("first");
        assert!(b > MS(1_400) && b <= MS(1_500), "{b:?}");
    }

    #[tokio::test]
    async fn a_skipped_step_with_a_wedged_destructor_does_not_block_the_sequencer() {
        let dropped = Arc::new(AtomicBool::new(false));
        let value = SlowDrop(Arc::clone(&dropped));
        // Handed to a helper thread before the step is built (as participate
        // does), so skipping the step can never run the destructor inline.
        let fut = drop_in_thread(move || drop(value));
        let plan = vec![
            StepPlan::best_effort("hog", MS(10_000)),
            StepPlan::best_effort("refresher", MS(1_000)),
        ];
        let mut td = Teardown::new(MS(100), plan);
        td.run("hog", |_| hang()).await;
        let t = Instant::now();
        assert!(td.run("refresher", |_| fut).await.is_none());
        assert!(t.elapsed() < MS(500), "blocked for {:?}", t.elapsed());
        assert_eq!(td.finish().skipped(), vec!["refresher"]);
        assert!(
            !dropped.load(Ordering::SeqCst),
            "still wedged in its thread"
        );
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
        let plan = participate_plan(true);
        let td = Teardown::new(DEFAULT_SHUTDOWN_DEADLINE, plan.clone());
        // The reservation in front of the first step is the critical total:
        // agreement 1.5 s + the joins group's 0.5 s (not 0.5 + 0.5).
        let reserved = td.reserved_after(0);
        assert_eq!(reserved, MS(2_000));
        // The live-catchup cap still fits in full.
        assert!(plan[0].cap + reserved <= DEFAULT_SHUTDOWN_DEADLINE);
        assert!(td.budget("live_catchup") + MS(50) >= plan[0].cap);
        td.finish();
        // Deadline + exit work + runtime drop stays inside the exit budget,
        // which is inside docker stop's 10 s grace.
        assert!(
            DEFAULT_SHUTDOWN_DEADLINE + EXIT_WORK_ALLOWANCE + RUNTIME_DROP_BOUND
                <= TOTAL_EXIT_BUDGET
        );
        assert!(TOTAL_EXIT_BUDGET < Duration::from_secs(10));
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

    #[test]
    fn a_missing_state_proof_service_reserves_nothing() {
        let with = Teardown::new(DEFAULT_SHUTDOWN_DEADLINE, participate_plan(true));
        let without = Teardown::new(DEFAULT_SHUTDOWN_DEADLINE, participate_plan(false));
        assert!(participate_plan(false)
            .iter()
            .all(|p| p.name != "state_proof_service"));
        // The group keeps the pool follower's 0.5 s either way; but a plan
        // with no critical group member left would reserve none of it.
        assert_eq!(with.reserved_after(0), without.reserved_after(0));
        let mut only_stateless = participate_plan(false);
        only_stateless.retain(|p| p.name != "pool_follower");
        let none = Teardown::new(DEFAULT_SHUTDOWN_DEADLINE, only_stateless);
        assert_eq!(none.reserved_after(0), MS(1_500));
    }

    #[tokio::test]
    async fn the_participate_plan_with_every_step_hung_ends_within_the_deadline() {
        // Scaled-down deadline, real plan shape: a hung catchup stop must not
        // starve the critical steps, and the tail is skipped.
        let plan: Vec<StepPlan> = participate_plan(true)
            .into_iter()
            .map(|p| StepPlan {
                cap: p.cap / 10,
                guaranteed: p.guaranteed / 10,
                ..p
            })
            .collect();
        let mut td = Teardown::new(DEFAULT_SHUTDOWN_DEADLINE / 10, plan);
        let t = Instant::now();
        td.run("live_catchup", |_| hang()).await;
        td.run("agreement", |_| hang()).await;
        td.run_group(vec![
            ("pool_follower", hang_boxed()),
            ("state_proof_service", hang_boxed()),
            ("participation_refresher", hang_boxed()),
            ("heartbeat_service", hang_boxed()),
        ])
        .await;
        for n in ["tx_syncer", "gossip", "rest_server", "catchpoint_export"] {
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

    fn hang_boxed() -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(std::future::pending::<()>())
    }

    #[test]
    fn the_deadline_env_parses_positive_seconds_only() {
        assert_eq!(deadline_from(None), DEFAULT_SHUTDOWN_DEADLINE);
        assert_eq!(deadline_from(Some("20")), Duration::from_secs(20));
        assert_eq!(deadline_from(Some(" 3 ")), Duration::from_secs(3));
        assert_eq!(deadline_from(Some("0")), DEFAULT_SHUTDOWN_DEADLINE);
        assert_eq!(deadline_from(Some("abc")), DEFAULT_SHUTDOWN_DEADLINE);
    }

    // --- ShutdownSignal --------------------------------------------------

    fn recording_signal(grace: Duration) -> (Arc<ShutdownSignal>, Arc<Mutex<Vec<i32>>>) {
        let exits = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&exits);
        let sig = ShutdownSignal::with_exit(grace, move |c| sink.lock().unwrap().push(c));
        (sig, exits)
    }

    #[tokio::test]
    async fn a_request_during_stuck_startup_cleans_up_and_exits_within_the_grace() {
        let (sig, exits) = recording_signal(MS(150));
        let cleaned = Arc::new(AtomicBool::new(false));
        let c = Arc::clone(&cleaned);
        sig.add_startup_cleanup(move || c.store(true, Ordering::SeqCst));
        let t = Instant::now();
        sig.request(143); // startup never reaches `wait`
        while exits.lock().unwrap().is_empty() {
            assert!(t.elapsed() < Duration::from_secs(3), "no exit");
            tokio::time::sleep(MS(10)).await;
        }
        assert!(t.elapsed() < MS(150) + MS(500), "took {:?}", t.elapsed());
        assert_eq!(*exits.lock().unwrap(), vec![143]);
        assert!(cleaned.load(Ordering::SeqCst), "pid-file cleanup must run");
    }

    #[tokio::test]
    async fn a_request_during_startup_hands_over_when_startup_reaches_the_wait() {
        let (sig, exits) = recording_signal(MS(300));
        let cleaned = Arc::new(AtomicBool::new(false));
        let c = Arc::clone(&cleaned);
        sig.add_startup_cleanup(move || c.store(true, Ordering::SeqCst));
        sig.request(130);
        // Startup finishes inside the grace: the wait returns at once.
        tokio::time::sleep(MS(50)).await;
        tokio::time::timeout(MS(500), sig.wait())
            .await
            .expect("an earlier request counts");
        tokio::time::sleep(MS(500)).await;
        assert!(exits.lock().unwrap().is_empty(), "normal teardown owns it");
        assert!(!cleaned.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn every_waiter_sees_a_request_made_before_it_waited() {
        let (sig, exits) = recording_signal(MS(100));
        sig.request(143);
        for _ in 0..3 {
            tokio::time::timeout(MS(500), sig.wait())
                .await
                .expect("each call sees the earlier request");
        }
        assert!(sig.is_requested());
        // A second request is ignored (first code and watchdog stand).
        sig.request(130);
        tokio::time::sleep(MS(300)).await;
        assert!(exits.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_request_after_the_wait_began_wakes_the_waiter_with_no_watchdog() {
        let (sig, exits) = recording_signal(MS(50));
        let waiter = {
            let sig = Arc::clone(&sig);
            tokio::spawn(async move { sig.wait().await })
        };
        tokio::time::sleep(MS(50)).await;
        sig.request(143);
        tokio::time::timeout(MS(500), waiter)
            .await
            .expect("woken")
            .unwrap();
        tokio::time::sleep(MS(200)).await;
        assert!(exits.lock().unwrap().is_empty());
    }
}
