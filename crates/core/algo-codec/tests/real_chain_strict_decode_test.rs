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

//! Historical-block safety net for the strict unknown-field decode (issue
//! #2394): every real block of every committed replay corpus (and of the large
//! local-only `testnet-head` corpus when it is present) must still decode through
//! the production catchup entry `decode_block_response`, which now rejects any
//! key go's structs lack, in the block, in every transaction and in the
//! certificate. go decodes the same bytes with its generated decoders, so a
//! failure here means a reader lacks a key go knows.

use algo_codec::{decode_block, decode_block_response};

/// `blocks.bin`: `ACRPBLK1`, then per round u64 round, u32 length and the
/// `/v2/blocks/{round}?format=msgpack` body (`{"block": ..., "cert": ...}`).
fn replay(dir: &str) -> Option<usize> {
    let path = format!(
        "{}/../../../benchmarks/corpus/{dir}/blocks.bin",
        env!("CARGO_MANIFEST_DIR")
    );
    let bytes = std::fs::read(&path).ok()?;
    let mut rest = bytes.strip_prefix(b"ACRPBLK1".as_slice()).expect("magic");
    let mut n = 0;
    let mut certs = 0;
    while !rest.is_empty() {
        let len = u32::from_be_bytes(rest[8..12].try_into().unwrap()) as usize;
        let body = &rest[12..12 + len];
        rest = &rest[12 + len..];
        let resp = decode_block_response(body)
            .unwrap_or_else(|e| panic!("{dir} record {n}: decode_block_response: {e:?}"));
        certs += resp.cert.is_some() as usize;
        let mut b = body;
        let v = rmpv::decode::read_value(&mut b).unwrap();
        let block = &v
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_str() == Some("block"))
            .expect("block key")
            .1;
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, block).unwrap();
        decode_block(&buf).unwrap_or_else(|e| panic!("{dir} record {n}: decode_block: {e:?}"));
        n += 1;
    }
    eprintln!("{dir}: {n} blocks, {certs} with a certificate");
    Some(n)
}

#[test]
fn committed_corpora_decode_strictly() {
    let mut total = 0;
    for dir in ["small", "small-catchpoint", "testnet-prefix50"] {
        total += replay(dir).unwrap_or_else(|| panic!("committed corpus {dir} is missing"));
    }
    assert!(total > 2_000, "{total} blocks");
}

/// The 250 MB testnet head corpus is not in git: replayed when present.
#[test]
fn local_testnet_head_decodes_strictly() {
    match replay("testnet-head") {
        Some(n) => eprintln!("testnet-head: {n} blocks decoded strictly"),
        None => eprintln!("benchmarks/corpus/testnet-head/blocks.bin not present: skipped"),
    }
}
