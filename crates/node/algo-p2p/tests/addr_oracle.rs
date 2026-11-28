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

//! Replays `fixtures/addr_oracle.jsonl`, written by go v5.1.1's real
//! `network/addr` `ParseHostOrURL` / `ParseHostOrURLOrMultiaddr` /
//! `IsMultiaddr` built with Go 1.27.4 (`tools/network-oracle`, issue #2554),
//! against `algo_p2p::addr`. Go 1.27's `net/url` rejects an unbracketed
//! multi-colon host, which v5.1.1's `TestParseHostOrURL` now pins
//! (`::11.22.33.44:123` is a "missing protocol scheme" error).

use algo_p2p::addr::{is_multiaddr, parse_host_or_url, parse_host_or_url_or_multiaddr};

#[test]
fn addr_parsing_matches_go_rows() {
    let rows = include_str!("fixtures/addr_oracle.jsonl");
    let mut bad = Vec::new();
    let mut n = 0;
    for line in rows.lines() {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        let addr = row["addr"].as_str().unwrap();
        n += 1;
        if is_multiaddr(addr) != row["is_multiaddr"].as_bool().unwrap() {
            bad.push(format!("{addr:?}: is_multiaddr"));
        }
        if row["ok"].as_bool().unwrap() {
            match parse_host_or_url(addr) {
                Ok(u) if u.scheme == row["scheme"] && u.host == row["host"] => {}
                other => bad.push(format!("{addr:?}: url {other:?} want {row}")),
            }
        } else if parse_host_or_url(addr).is_ok() {
            bad.push(format!("{addr:?}: go rejects, rust parses"));
        }
        let got = parse_host_or_url_or_multiaddr(addr);
        let go_ok = row["multi_ok"].as_bool().unwrap();
        match (&got, go_ok) {
            (Ok(h), true) => {
                if h != row["multi"].as_str().unwrap() {
                    bad.push(format!("{addr:?}: host {h:?} want {:?}", row["multi"]));
                }
            }
            (Err(e), false) => {
                // the error text go's TestParseHostOrURL asserts on
                let want = row["multi_err"].as_str().unwrap();
                for needle in [
                    "invalid port",
                    "missing protocol scheme",
                    "could not parse a host from url",
                    "host name starts with a colon",
                ] {
                    if want.contains(needle) && !e.to_string().contains(needle) {
                        bad.push(format!("{addr:?}: err {e:?} lacks {needle:?} (go: {want})"));
                    }
                }
            }
            _ => bad.push(format!("{addr:?}: go ok={go_ok}, rust {got:?}")),
        }
    }
    assert_eq!(n, 115);
    assert!(
        bad.is_empty(),
        "{} mismatches:
{}",
        bad.len(),
        bad.join(
            "
"
        )
    );
}
