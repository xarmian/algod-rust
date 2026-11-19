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

//! Real-chain strict-decode sweep (issue #2439): every block of a fetched
//! range (`scripts/strict-decode/fetch_block_range.py`) must decode through the
//! production readers (`decode_block_response`, `decode_block`) and re-encode
//! to go's bytes. The serving nodes accepted every block, so a failure is a
//! reader stricter than go. Opt-in, it needs the network:
//!
//! - `ALGOD_RUST_DECODE_SWEEP`: comma-separated `blocks.bin` files (one
//!   network per run);
//! - `ALGOD_RUST_DECODE_SWEEP_NETWORK=aramidmain`: load that preset's bundled
//!   `consensus.json` first, as `algod-rust --network aramidmain` does (its
//!   protocols raise go's allocbounds). The install is process-global, so one
//!   network per process.
//!
//! Unset, the test skips. `scripts/strict-decode/decode_sweep.sh` runs it for
//! mainnet, testnet, voimain and aramidmain.

use algo_codec::{canonical_encode_block, decode_block, decode_block_response};
use algo_types::consensus::{
    built_in_consensus_protocols, install_consensus_overrides,
    preload_consensus_protocols_with_bundle,
};

const ARAMIDMAIN: &str =
    include_str!("../../../../bin/algod-rust/consensus/aramidmain-consensus.json");

/// The `block` value of a `{"block", "cert"}` response, as the served bytes
/// (not re-encoded: rmpv would turn a non-UTF-8 `str` into a `bin`).
fn block_value(body: &[u8]) -> &[u8] {
    let mut rd = body;
    let n = rmp::decode::read_map_len(&mut rd).expect("response map");
    for _ in 0..n {
        let klen = rmp::decode::read_str_len(&mut rd).expect("key") as usize;
        let (key, after) = rd.split_at(klen);
        let vlen = algo_types::msgpack_value_len(after).expect("value");
        if key == b"block" {
            return &after[..vlen];
        }
        rd = &after[vlen..];
    }
    panic!("no block key");
}

/// Decode every record; returns (blocks, failures as "round: error").
fn sweep(path: &str) -> (usize, Vec<String>) {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut rest = bytes
        .strip_prefix(b"ACRPBLK1".as_slice())
        .unwrap_or_else(|| panic!("{path}: not an ACRPBLK1 file"));
    let mut n = 0;
    let mut failures = Vec::new();
    while !rest.is_empty() {
        let round = u64::from_be_bytes(rest[..8].try_into().unwrap());
        let len = u32::from_be_bytes(rest[8..12].try_into().unwrap()) as usize;
        let body = &rest[12..12 + len];
        rest = &rest[12 + len..];
        n += 1;
        if let Err(e) = decode_block_response(body) {
            failures.push(format!("{round}: decode_block_response: {e:?}"));
            continue;
        }
        let raw = block_value(body);
        match decode_block(raw) {
            Err(e) => failures.push(format!("{round}: decode_block: {e:?}")),
            Ok(blk) if canonical_encode_block(&blk) != raw => {
                failures.push(format!("{round}: canonical re-encode differs"))
            }
            Ok(_) => {}
        }
    }
    (n, failures)
}

#[test]
fn fetched_real_blocks_decode_strictly() {
    let Ok(files) = std::env::var("ALGOD_RUST_DECODE_SWEEP") else {
        eprintln!("ALGOD_RUST_DECODE_SWEEP not set: skipped");
        return;
    };
    match std::env::var("ALGOD_RUST_DECODE_SWEEP_NETWORK").as_deref() {
        Ok("aramidmain") => {
            let merged = preload_consensus_protocols_with_bundle(
                None,
                built_in_consensus_protocols(),
                Some(ARAMIDMAIN),
            )
            .unwrap();
            install_consensus_overrides(&merged);
        }
        Ok("") | Err(_) => {}
        Ok(other) => panic!("ALGOD_RUST_DECODE_SWEEP_NETWORK={other}: no bundled consensus.json"),
    }
    let mut all = Vec::new();
    for path in files.split(',').filter(|p| !p.is_empty()) {
        let (n, failures) = sweep(path);
        eprintln!("{path}: {n} blocks, {} rejected", failures.len());
        all.extend(failures.into_iter().map(|f| format!("{path} round {f}")));
    }
    assert!(
        all.is_empty(),
        "go-accepted blocks rejected:\n{}",
        all.join("\n")
    );
}
