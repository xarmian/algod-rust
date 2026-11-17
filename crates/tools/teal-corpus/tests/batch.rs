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

//! Robustness contract of the batch runner (#2366): a panicking or
//! overrunning input is recorded for that input only, the batch continues,
//! and the result order is deterministic.

use std::sync::Arc;
use std::time::Duration;

use teal_corpus::{run_batch, run_batch_with, BatchOptions, Input, Row};

fn input(sha: &str) -> Input {
    Input {
        sha256: sha.to_string(),
        bytes: Arc::new(sha.as_bytes().to_vec()),
    }
}

fn ok_row(i: &Input) -> Row {
    Row {
        ok: true,
        sha256: i.sha256.clone(),
        ..Row::default()
    }
}

#[test]
fn a_panicking_input_is_recorded_and_the_batch_continues() {
    let inputs = vec![input("c"), input("a"), input("boom"), input("b")];
    let rows = run_batch(inputs, 2, Duration::from_secs(5), |i| {
        if i.sha256 == "boom" {
            panic!("kaboom");
        }
        ok_row(i)
    });
    let shas: Vec<&str> = rows.iter().map(|r| r.sha256.as_str()).collect();
    assert_eq!(shas, ["a", "b", "boom", "c"], "sorted by sha256");
    let boom = &rows[2];
    assert!(!boom.ok);
    assert_eq!(boom.panic.as_deref(), Some("kaboom"));
    assert_eq!(rows.iter().filter(|r| r.ok).count(), 3);
}

#[test]
fn a_hanging_input_times_out_and_the_batch_continues() {
    let inputs = vec![input("a"), input("hang"), input("b")];
    let started = std::time::Instant::now();
    let rows = run_batch(inputs, 2, Duration::from_millis(200), |i| {
        if i.sha256 == "hang" {
            std::thread::sleep(Duration::from_secs(30));
        }
        ok_row(i)
    });
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "must not wait for the hung input"
    );
    assert_eq!(rows.len(), 3);
    let shas: Vec<&str> = rows.iter().map(|r| r.sha256.as_str()).collect();
    assert_eq!(shas, ["a", "b", "hang"]);
    assert!(!rows[2].ok);
    assert_eq!(rows[2].timeout, Some(true));
    assert!(rows[0].ok && rows[1].ok);
}

#[test]
fn panic_and_timeout_rows_make_the_batch_report_a_robustness_failure() {
    let rows = run_batch(
        vec![input("a"), input("boom")],
        1,
        Duration::from_secs(5),
        |i| {
            if i.sha256 == "boom" {
                panic!("x");
            }
            ok_row(i)
        },
    );
    assert!(teal_corpus::has_robustness_failure(&rows));
    assert!(!teal_corpus::has_robustness_failure(&rows[..1]));
}

// #2382: the batch used to spawn one 64 MiB-stack thread per input and drop its
// JoinHandle (pthread_detach). glibc munmaps a stack larger than its 40 MiB
// stack cache the moment the thread exits, and pthread_detach on a thread that
// is exiting at that instant reads the already unmapped descriptor: SIGSEGV
// (exit 139, no row) at 200k+ inputs. Workers are now long-lived: one thread per
// job, reused for every input, joined at the end of the batch.
#[test]
fn inputs_are_processed_on_a_bounded_set_of_reused_worker_threads() {
    use std::collections::HashSet;
    use std::sync::Mutex;
    let ids = Arc::new(Mutex::new(HashSet::new()));
    let ids2 = Arc::clone(&ids);
    let inputs: Vec<Input> = (0..5000).map(|n| input(&format!("{n:05}"))).collect();
    let rows = run_batch(inputs, 4, Duration::from_secs(30), move |i| {
        ids2.lock().unwrap().insert(std::thread::current().id());
        ok_row(i)
    });
    assert_eq!(rows.len(), 5000);
    assert!(rows.iter().all(|r| r.ok));
    let distinct = ids.lock().unwrap().len();
    assert!(
        distinct <= 4,
        "one reusable worker per job, saw {distinct} worker threads"
    );
}

#[test]
fn a_large_trivial_batch_on_many_jobs_completes_without_crashing() {
    let inputs: Vec<Input> = (0..100_000).map(|n| input(&format!("{n:06}"))).collect();
    let rows = run_batch(inputs, 24, Duration::from_secs(30), ok_row);
    assert_eq!(rows.len(), 100_000);
    assert!(rows.iter().all(|r| r.ok));
}

#[test]
fn a_worker_spawn_failure_is_a_recorded_row_error_not_a_crash() {
    let opts = BatchOptions {
        jobs: 2,
        timeout: Duration::from_secs(5),
        // Not a stack any platform can map: the spawn itself fails.
        stack_bytes: usize::MAX / 4,
        ..BatchOptions::default()
    };
    let rows = run_batch_with(vec![input("a"), input("b"), input("c")], &opts, ok_row);
    assert_eq!(rows.len(), 3);
    for r in &rows {
        assert!(!r.ok);
        let msg = r.panic.as_deref().expect("a row error");
        assert!(msg.starts_with("failed to spawn worker thread"), "{msg}");
    }
    assert!(teal_corpus::has_robustness_failure(&rows));
}

#[test]
fn hung_workers_beyond_the_limit_stop_the_batch_with_recorded_row_errors() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let ran = Arc::new(AtomicUsize::new(0));
    let ran2 = Arc::clone(&ran);
    let opts = BatchOptions {
        jobs: 1,
        timeout: Duration::from_millis(100),
        max_abandoned: 2,
        ..BatchOptions::default()
    };
    let inputs: Vec<Input> = (0..6).map(|n| input(&format!("h{n}"))).collect();
    let started = std::time::Instant::now();
    let rows = run_batch_with(inputs, &opts, move |i| {
        ran2.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_secs(20));
        ok_row(i)
    });
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(rows.len(), 6);
    assert_eq!(rows.iter().filter(|r| r.timeout == Some(true)).count(), 2);
    let refused: Vec<_> = rows
        .iter()
        .filter(|r| {
            r.panic
                .as_deref()
                .is_some_and(|m| m.contains("abandoned worker limit"))
        })
        .collect();
    assert_eq!(refused.len(), 4, "the other inputs are refused, not run");
    assert_eq!(ran.load(Ordering::SeqCst), 2, "no further hung worker");
    assert!(teal_corpus::has_robustness_failure(&rows));
}

// #2411: workers claim their own inputs and the supervisor only wakes at the
// running input's deadline, so the timeout must be per input (measured from
// that input's start), never per batch or per worker.
#[test]
fn the_timeout_is_per_input_even_when_the_batch_runs_longer_than_it() {
    let mut inputs: Vec<Input> = (0..12).map(|n| input(&format!("s{n:02}"))).collect();
    inputs.push(input("zz-hang"));
    let started = std::time::Instant::now();
    let rows = run_batch(inputs, 1, Duration::from_millis(150), |i| {
        if i.sha256 == "zz-hang" {
            std::thread::sleep(Duration::from_secs(30));
        } else {
            std::thread::sleep(Duration::from_millis(40));
        }
        ok_row(i)
    });
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(rows.len(), 13);
    assert!(
        rows[..12].iter().all(|r| r.ok),
        "12 x 40 ms inputs under a 150 ms per-input budget all finish"
    );
    assert_eq!(rows[12].timeout, Some(true));
}

// #2411: a panicking input does not cost the worker: the next inputs run on
// the same thread (one worker per job, no respawn).
#[test]
fn a_panic_keeps_the_worker() {
    use std::collections::HashSet;
    use std::sync::Mutex;
    let ids = Arc::new(Mutex::new(HashSet::new()));
    let ids2 = Arc::clone(&ids);
    let inputs = vec![input("a"), input("b-boom"), input("c"), input("d")];
    let rows = run_batch(inputs, 1, Duration::from_secs(5), move |i| {
        ids2.lock().unwrap().insert(std::thread::current().id());
        if i.sha256 == "b-boom" {
            panic!("kaboom");
        }
        ok_row(i)
    });
    assert_eq!(rows.iter().filter(|r| r.ok).count(), 3);
    assert_eq!(rows[1].panic.as_deref(), Some("kaboom"));
    assert_eq!(ids.lock().unwrap().len(), 1);
}
