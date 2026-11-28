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

//! Replays `fixtures/network_oracle/zstd_proposal.jsonl`, written by go
//! v5.1.1's real `network.DecompressProposal` (`tools/network-oracle`, issue
//! #2554) over bare/truncated/trailing/concatenated frames and the exact size
//! bound, against `algo_network::compression::decompress_proposal`.

use algo_network::compression::decompress_proposal;
use sha2::{Digest, Sha256};

#[test]
fn decompress_proposal_matches_go_rows() {
    let rows = include_str!("fixtures/network_oracle/zstd_proposal.jsonl");
    let mut n = 0;
    for line in rows.lines() {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        let name = row["name"].as_str().unwrap();
        let input = hex::decode(row["hex"].as_str().unwrap()).unwrap();
        let got = decompress_proposal(&input);
        let want_ok = row["ok"].as_bool().unwrap();
        match (&got, want_ok) {
            (Ok(out), true) => {
                assert_eq!(out.len() as u64, row["len"].as_u64().unwrap(), "{name}");
                assert_eq!(
                    hex::encode(Sha256::digest(out)),
                    row["sha256"].as_str().unwrap(),
                    "{name}"
                );
            }
            (Err(_), false) => {}
            _ => panic!(
                "{name}: go ok={want_ok}, rust {:?}",
                got.as_ref().map(|v| v.len())
            ),
        }
        n += 1;
    }
    assert_eq!(n, 25);
}
