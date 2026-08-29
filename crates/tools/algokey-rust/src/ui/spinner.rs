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

//! Spinning-cursor wrapper for long-running operations.
//!
//! Mirrors `../go-algorand/util/cmdUtils.go::RunFuncWithSpinningCursor`:
//! draws a `\|/-` rotating cursor on stderr every ~100ms while a worker
//! closure runs, then erases the cursor on completion.
//!
//! Suppresses output entirely when stderr is not a TTY so piped logs
//! stay clean (Go's implementation makes the same check implicitly via
//! the terminal's typical line buffering behaviour; we make it
//! explicit via `IsTerminal`).

use std::io::{IsTerminal, Write};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Run `f` on a worker thread while drawing a `\|/-` spinner on stderr.
///
/// Returns the closure's return value. Panics in `f` propagate to the
/// caller via `thread::scope`'s join semantics (the spinner thread
/// remains responsive and exits cleanly).
///
/// When stderr is not a TTY the spinner is skipped and `f` runs
/// synchronously on the calling thread.
pub fn run_with_spinner<F, T>(f: F) -> T
where
    F: FnOnce() -> T + Send,
    T: Send,
{
    // Non-TTY: just run synchronously — no thread overhead, no cursor
    // garbage in piped logs.
    if !std::io::stderr().is_terminal() {
        return f();
    }

    run_with_spinner_inner(f, Duration::from_millis(100))
}

/// Internal implementation: spawn the worker on a scoped thread, tick the
/// cursor on the main thread until the worker signals completion.
///
/// `tick` is parameterized so tests can use a shorter interval. Production
/// callers use `Duration::from_millis(100)` (matches Go).
fn run_with_spinner_inner<F, T>(f: F, tick: Duration) -> T
where
    F: FnOnce() -> T + Send,
    T: Send,
{
    const CURSOR: [u8; 4] = *b"\\|/-";
    let (done_tx, done_rx) = mpsc::channel::<()>();

    let result = thread::scope(|scope| {
        let handle = scope.spawn(move || {
            let value = f();
            // Best-effort signal — receiver always lives until join.
            let _ = done_tx.send(());
            value
        });

        // Re-acquire the stderr lock per tick (NOT held for the worker's
        // whole lifetime) so a worker that writes to stderr — via
        // `eprintln!`, `std::io::stderr()`, etc. — cannot deadlock waiting
        // for us to release the lock while we wait for its done signal.
        let mut idx = 0usize;
        loop {
            // Wait for either a "done" notification or the tick interval.
            match done_rx.recv_timeout(tick) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let mut stderr = std::io::stderr().lock();
                    let _ = stderr.write_all(&[CURSOR[idx], b'\x08']);
                    let _ = stderr.flush();
                    drop(stderr);
                    idx = (idx + 1) % CURSOR.len();
                }
            }
        }
        // Erase the lingering cursor: space-then-backspace overwrites
        // whatever character is sitting at the terminal cursor.
        {
            let mut stderr = std::io::stderr().lock();
            let _ = stderr.write_all(b" \x08");
            let _ = stderr.flush();
        }

        handle.join()
    });

    // Propagate any panic from the worker thread.
    match result {
        Ok(v) => v,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_with_spinner_returns_closure_value_on_non_tty() {
        // Test runner pipes stderr, so this exercises the non-TTY path.
        let n = run_with_spinner(|| 42_u64);
        assert_eq!(n, 42);
    }

    #[test]
    fn run_with_spinner_returns_value_even_when_closure_takes_time() {
        let n = run_with_spinner(|| {
            thread::sleep(Duration::from_millis(50));
            "done"
        });
        assert_eq!(n, "done");
    }

    #[test]
    fn worker_panic_propagates_to_caller() {
        // Forces the tty branch via the internal helper so we exercise
        // the propagation path even under `cargo test` (which pipes stderr).
        let result = std::panic::catch_unwind(|| {
            run_with_spinner_inner(
                || {
                    panic!("worker bomb");
                },
                Duration::from_millis(10),
            )
        });
        let err = result.expect_err("worker panic should propagate");
        let msg = err
            .downcast_ref::<&'static str>()
            .copied()
            .or_else(|| err.downcast_ref::<String>().map(String::as_str))
            .unwrap_or("(non-string panic payload)");
        assert!(msg.contains("worker bomb"), "actual: {msg}");
    }

    #[test]
    fn worker_can_write_to_stderr_without_deadlock() {
        // Regression test for the Codex-round-1 finding: the spinner held
        // the stderr lock for the entire worker lifetime, which would
        // deadlock against any `eprintln!` / `std::io::stderr()` write
        // from inside the closure. Drive the internal helper (TTY path)
        // with a short tick so we definitely hit the spinner-write loop
        // while the worker is also writing to stderr.
        let n = run_with_spinner_inner(
            || {
                use std::io::Write as _;
                for _ in 0..50 {
                    // Direct stderr lock — same code path eprintln! takes.
                    let mut s = std::io::stderr().lock();
                    let _ = s.write_all(b"\n");
                    let _ = s.flush();
                    drop(s);
                    thread::sleep(Duration::from_millis(2));
                }
                123_u32
            },
            Duration::from_millis(5),
        );
        assert_eq!(n, 123, "worker must complete despite contending for stderr");
    }

    #[test]
    fn closure_runs_exactly_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let counter = AtomicUsize::new(0);
        run_with_spinner(|| {
            counter.fetch_add(1, Ordering::Relaxed);
        });
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }
}
