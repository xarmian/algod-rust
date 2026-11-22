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

//! `dt` (eval delta) nesting depth against go v5.0.5-stable (issue #2539).
//!
//! `fixtures/dt_nesting_go.jsonl` (made by `tools/dt-nesting-oracle`) holds a
//! block whose one transaction has an eval delta nested N inner-transaction
//! levels deep, with go's verdict and canonical re-encode. go accepts up to
//! 124 levels and rejects 125 (`Max depth exceeded`: msgp's 255-container cap);
//! the deepest delta holds a `bin` `gd` key go re-types to `str`, so a decoder
//! that stopped typing at some depth would re-encode different bytes.
//! `decode_block` must give go's verdict and bytes at every depth, and in
//! about as many steps as go: the first version of this test never finished
//! (a non-canonical `dt` took 2^depth steps).

use algo_codec::{canonical_encode_block, decode_block};
use base64::Engine as _;

const ROWS: &str = include_str!("fixtures/dt_nesting_go.jsonl");

fn check(name: &str, decode: impl Fn(&[u8]) -> Result<algo_types::Block, algo_error::AlgoError>) {
    let mut failures = Vec::new();
    for line in ROWS.lines() {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        let depth = row["depth"].as_u64().unwrap();
        let body = base64::engine::general_purpose::STANDARD
            .decode(row["body"].as_str().unwrap())
            .unwrap();
        match (decode(&body), row["reencoded"].as_str()) {
            (Ok(block), Some(go)) => {
                let want = base64::engine::general_purpose::STANDARD.decode(go).unwrap();
                if canonical_encode_block(&block) != want {
                    failures.push(format!("depth {depth}: re-encode differs from go's"));
                }
            }
            (Err(_), None) => {}
            (Ok(_), None) => failures.push(format!(
                "depth {depth}: go rejects ({}), {name} accepts",
                row["err"]
            )),
            (Err(e), Some(_)) => failures.push(format!("depth {depth}: go accepts, {name}: {e}")),
        }
    }
    assert!(failures.is_empty(), "{name}:\n{}", failures.join("\n"));
}

#[test]
fn decode_block_matches_go_at_every_dt_depth() {
    // a debug build of the typed decoder spends a few KiB of stack per level
    // (go's 124 levels overflow the 2 MiB of a test thread)
    std::thread::Builder::new()
        .stack_size(8 << 20)
        .spawn(|| check("decode_block", decode_block))
        .unwrap()
        .join()
        .unwrap();
}
