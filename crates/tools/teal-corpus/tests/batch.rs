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

use teal_corpus::{run_batch, Input, Row};

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
