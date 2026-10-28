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

//! Output equivalence of the micro pairs (issue #2103), without Go.
//!
//! `benchmarks/fixtures/micro/go-digests.json` is what go-algorand's side
//! (`go run ./cmd/equiv -write ...` in `benchmarks/go-micro`) printed for
//! each pair at the pinned tag. Every Rust case must produce exactly that
//! digest on the same fixture, so a default `cargo test` catches a Rust
//! change that makes a pair do different work (or get a different answer)
//! long before the micro tier runs. The CI micro job re-runs the Go side
//! live and compares the two directly.

use std::collections::BTreeMap;

fn go_digests() -> BTreeMap<String, String> {
    let p = algo_bench_pairs::fixture_dir().join("go-digests.json");
    let raw = std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    serde_json::from_slice(&raw).expect("go-digests.json is a JSON object of strings")
}

#[test]
fn every_pair_matches_go_digest() {
    let want = go_digests();
    let got = algo_bench_pairs::all_digests(&algo_bench_pairs::fixture_dir());
    let mut diffs = Vec::new();
    for (id, g) in &got {
        match want.get(id) {
            Some(w) if w == g => {}
            Some(w) => diffs.push(format!("{id}: rust {g:?} != go {w:?}")),
            None => diffs.push(format!("{id}: no Go digest recorded")),
        }
    }
    for id in want.keys() {
        if !got.contains_key(id) {
            diffs.push(format!("{id}: Go pair has no Rust case"));
        }
    }
    assert!(
        diffs.is_empty(),
        "micro pair digests differ:\n{}",
        diffs.join("\n")
    );
}

#[test]
fn ids_are_sorted_unique_and_grouped() {
    let ids = algo_bench_pairs::IDS;
    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted, ids, "IDS must be sorted and unique");
    for id in ids {
        let (g, n) = id.split_once('/').expect("<group>/<name>");
        assert!(!g.is_empty() && !n.is_empty() && !n.contains('/'), "{id}");
    }
}

#[test]
fn every_case_runs() {
    let dir = algo_bench_pairs::fixture_dir();
    for id in algo_bench_pairs::IDS {
        let mut c = algo_bench_pairs::build(&dir, id).unwrap_or_else(|e| panic!("{e}"));
        c.run();
        c.run(); // repeatable: the benchmark calls it many times
    }
}

#[test]
fn frames_round_trip_and_reject_truncation() {
    let mut buf = Vec::new();
    for part in [&b"ab"[..], b"", b"xyz"] {
        buf.extend_from_slice(&(part.len() as u32).to_le_bytes());
        buf.extend_from_slice(part);
    }
    let f = algo_bench_pairs::frames(&buf).unwrap();
    assert_eq!(f, vec![b"ab".to_vec(), vec![], b"xyz".to_vec()]);
    assert!(algo_bench_pairs::frames(&buf[..buf.len() - 1]).is_err());
    assert!(algo_bench_pairs::frames(&[1, 0]).is_err());
}
