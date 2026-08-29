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

//! Byte-level vFuture conformance for the `Load`/`CongestionTax`
//! ("ld"/"ct") block-header fields added in #534/PR #547 (issue #548).
//!
//! #534 landed `LoadTracking` support pinned only to Rust-side unit tests
//! anchored on values taken from go-algorand's own Go test source
//! (`TestNextCongestionTax`'s oracle table) — solid coverage of the
//! *arithmetic*, but not the same guarantee as a fixture captured from a
//! real go-algorand `vFuture` binary, because nothing in the
//! fixture/conformance harness ever stood up a `vFuture`-consensus node.
//!
//! The fixtures this test reads are raw `/v2/blocks/{round}?format=msgpack`
//! bytes captured from a real `algorand/algod:4.7.0-stable` node running
//! under the `future` protocol (`docker/docker-compose.vfuture.yml`,
//! `docker/scripts/capture-vfuture-fixtures.sh`) -- see
//! `docs/CONFORMANCE_STRATEGY.md` §14.5 and `docs/DEV_WORKFLOW.md`
//! §"vFuture Fixture Capture" for how they were produced and how to
//! regenerate them.
//!
//! This is a hard requirement, not a skip-if-missing test (mirroring
//! `merkle_page_fixture_test.rs`'s convention for other captured-fixture
//! suites): a missing fixture directory fails loudly with regeneration
//! instructions, per this repo's TDD-first culture (this test must fail
//! for the right reason before the capture pipeline exists).

use std::path::PathBuf;

use algo_codec::{decode_block_response, decode_block_response_fast, decode_raw};
use algo_ledger::next_congestion_tax;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vfuture")
}

/// Every captured round, ascending. Panics with regeneration instructions
/// if the fixture directory is missing or empty -- see the module doc.
fn captured_rounds() -> Vec<u64> {
    let dir = fixtures_dir();
    let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| {
        panic!(
            "vFuture fixtures missing at {} ({e}).\n\
             Run `docker/scripts/capture-vfuture-fixtures.sh` (see \
             docs/DEV_WORKFLOW.md \u{201c}vFuture Fixture Capture\u{201d}) to \
             regenerate them.",
            dir.display()
        )
    });

    let mut rounds: Vec<u64> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let stem = name.strip_prefix("block_")?.strip_suffix(".msgpack")?;
            stem.parse::<u64>().ok()
        })
        .collect();
    rounds.sort_unstable();
    assert!(
        !rounds.is_empty(),
        "no block_<round>.msgpack fixtures found in {} -- run \
         docker/scripts/capture-vfuture-fixtures.sh",
        dir.display()
    );
    rounds
}

fn load_raw(round: u64) -> Vec<u8> {
    let path = fixtures_dir().join(format!("block_{round}.msgpack"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Every captured round must actually be a `future`-protocol block, and
/// the ordinary serde-derive decoder (`decode_block_response`) and the
/// hand-rolled byte-matching "fast" decoder (`decode_block_response_fast`)
/// must agree on the Load/CongestionTax values -- a real go-algorand
/// vFuture payload is exactly the input class neither decoder had been
/// exercised against before #548.
#[test]
fn vfuture_fixtures_decode_and_agree_on_load_and_tax() {
    for round in captured_rounds() {
        let raw = load_raw(round);

        let br = decode_block_response(&raw)
            .unwrap_or_else(|e| panic!("serde decode of round {round} failed: {e}"));
        assert_eq!(
            br.block.current_protocol, "future",
            "round {round} was not captured under the vFuture (\"future\") protocol"
        );

        let br_fast = decode_block_response_fast(&raw)
            .unwrap_or_else(|e| panic!("fast decode of round {round} failed: {e}"));
        assert_eq!(
            br.block.load, br_fast.block.load,
            "serde vs. fast decoder Load mismatch at round {round}"
        );
        assert_eq!(
            br.block.congestion_tax, br_fast.block.congestion_tax,
            "serde vs. fast decoder CongestionTax mismatch at round {round}"
        );
    }
}

/// The whole point of #548: at least one captured round must carry a
/// non-zero `Load` and at least one must carry a non-zero `CongestionTax`
/// -- proving the capture pipeline actually reached vFuture's
/// congestion-tracking behavior rather than just an idle vFuture node.
#[test]
fn vfuture_fixtures_carry_nonzero_load_and_congestion_tax() {
    let rounds = captured_rounds();
    let mut max_load = 0u64;
    let mut max_tax = 0u64;
    for round in &rounds {
        let br = decode_block_response(&load_raw(*round)).unwrap();
        max_load = max_load.max(br.block.load);
        max_tax = max_tax.max(br.block.congestion_tax);
    }
    assert!(
        max_load > 0,
        "no captured vFuture round ({rounds:?}) has non-zero Load -- the \
         capture didn't push a block over the MaxTxnBytesPerBlock \
         threshold; see docker/config/vfuture-consensus.json"
    );
    assert!(
        max_tax > 0,
        "no captured vFuture round ({rounds:?}) has non-zero CongestionTax \
         -- Load never exceeded 50% full for a full round; see \
         NextCongestionTax in data/bookkeeping/block.go"
    );
}

/// Byte-level Layer-1 check (docs/CONFORMANCE_STRATEGY.md §3): read the
/// "ld"/"ct" values straight out of the raw go-algorand-produced msgpack
/// via the generic `rmpv` decoder, independent of our typed `Block`
/// deserializer entirely, and assert they match what the typed decoder
/// reports. This guards against a typed-decoder-only bug silently
/// masking a real encoding mismatch.
#[test]
fn vfuture_typed_decode_matches_raw_msgpack_ld_ct_bytes() {
    for round in captured_rounds() {
        let raw = load_raw(round);
        let value = decode_raw(&raw).unwrap_or_else(|e| panic!("raw decode round {round}: {e}"));
        let block_map = value
            .as_map()
            .unwrap_or_else(|| panic!("round {round}: top-level msgpack value is not a map"))
            .iter()
            .find(|(k, _)| k.as_str() == Some("block"))
            .unwrap_or_else(|| panic!("round {round}: no \"block\" key in response"))
            .1
            .as_map()
            .unwrap_or_else(|| panic!("round {round}: \"block\" value is not a map"));

        let raw_ld = block_map
            .iter()
            .find(|(k, _)| k.as_str() == Some("ld"))
            .and_then(|(_, v)| v.as_u64())
            .unwrap_or(0);
        let raw_ct = block_map
            .iter()
            .find(|(k, _)| k.as_str() == Some("ct"))
            .and_then(|(_, v)| v.as_u64())
            .unwrap_or(0);

        let br = decode_block_response(&raw).unwrap();
        assert_eq!(
            raw_ld, br.block.load,
            "round {round}: raw msgpack \"ld\" byte value disagrees with typed decode"
        );
        assert_eq!(
            raw_ct, br.block.congestion_tax,
            "round {round}: raw msgpack \"ct\" byte value disagrees with typed decode"
        );
    }
}

/// The regression-catching heart of this suite: for every pair of
/// consecutive captured rounds, Rust's `next_congestion_tax` (ported from
/// go-algorand's `NextCongestionTax`) applied to round N's `Load`/
/// `CongestionTax` must predict round N+1's go-algorand-produced
/// `CongestionTax` exactly. This would fail immediately if
/// `next_congestion_tax` regressed -- unlike the pre-existing oracle-table
/// unit tests, the expected values here come from a real go-algorand
/// binary, not from a table transcribed by hand.
#[test]
fn vfuture_next_congestion_tax_predicts_go_algorand_output_across_consecutive_rounds() {
    let rounds = captured_rounds();
    let mut verified_pairs = 0u32;

    for pair in rounds.windows(2) {
        let (r0, r1) = (pair[0], pair[1]);
        if r1 != r0 + 1 {
            continue; // only consecutive rounds let CongestionTax's
                      // one-round lag line up.
        }

        let h0 = decode_block_response(&load_raw(r0)).unwrap().block;
        let h1 = decode_block_response(&load_raw(r1)).unwrap().block;

        let predicted = next_congestion_tax(h0.load, h0.congestion_tax);
        assert_eq!(
            predicted, h1.congestion_tax,
            "next_congestion_tax(round {r0}'s Load={}, CongestionTax={}) = {predicted}, \
             but go-algorand's round {r1} actually produced CongestionTax={}",
            h0.load, h0.congestion_tax, h1.congestion_tax
        );
        verified_pairs += 1;
    }

    assert!(
        verified_pairs > 0,
        "no consecutive round pair among {rounds:?} -- need at least two \
         adjacent captured rounds to cross-check next_congestion_tax"
    );
}
