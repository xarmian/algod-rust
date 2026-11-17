// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Decode parity of the libp2p peer-meta-headers message with go-algorand
//! (issue #2396).
//!
//! go reads it with the generated `peerMetaHeaders.UnmarshalMsg`
//! (`network/p2pMetainfo.go`, `readPeerMetaHeaders`): a `map[string][]string`
//! with at most 64 keys and 16 values per key, where `nil` stands for an empty
//! value list. `tests/fixtures/strict_decode/` holds valid headers
//! (`seeds.jsonl`) and mutants of them with go's verdict (`cases.jsonl`), from
//! `scripts/strict-decode/strict_decode_fixtures.py --set p2p`
//! (tools/strict-decode-oracle/network_oracle_test.go.txt).

use algo_p2p::wsproto::decode_headers;

#[path = "../../../../scripts/strict-decode/replay.rs"]
mod replay;

use replay::{valued, Verdicts};

/// The decoded headers, encoded like go's `peerMetaHeaders.MarshalMsg`: keys
/// in byte order, strings as `str` of their original bytes (the oracle writes
/// a nil map / value list as an empty one).
fn go_encode(h: &algo_p2p::wsproto::PeerMetaHeaders) -> Vec<u8> {
    use algo_types::raw_text::decode;
    fn string(out: &mut Vec<u8>, s: &[u8]) {
        rmp::encode::write_str_len(out, s.len() as u32).expect("vec write");
        out.extend_from_slice(s);
    }
    let mut keys: Vec<_> = h.iter().map(|(k, v)| (decode(k), v)).collect();
    keys.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = Vec::new();
    rmp::encode::write_map_len(&mut out, keys.len() as u32).expect("vec write");
    for (k, vals) in keys {
        string(&mut out, &k);
        rmp::encode::write_array_len(&mut out, vals.len() as u32).expect("vec write");
        for v in vals {
            string(&mut out, &decode(v));
        }
    }
    out
}

fn verdicts(kind: &str, b: &[u8]) -> Verdicts {
    match kind {
        "peermeta" => vec![(
            "wsproto::decode_headers",
            valued(decode_headers(b), go_encode),
        )],
        other => panic!("unknown kind {other}"),
    }
}

/// Every committed mutant (and, with `STRICT_FUZZ_FILE`, every fuzz case): go's
/// verdict and decoded value equal algod-rust's.
#[test]
fn peer_meta_headers_decoder_matches_go_on_every_mutated_message() {
    replay::replay_committed_and_fuzz(env!("CARGO_MANIFEST_DIR"), "p2p", verdicts);
}
