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

use replay::{verdict, Verdicts};

fn verdicts(kind: &str, b: &[u8]) -> Verdicts {
    match kind {
        "peermeta" => vec![("wsproto::decode_headers", verdict(decode_headers(b)))],
        other => panic!("unknown kind {other}"),
    }
}

/// Every committed mutant (and, with `STRICT_FUZZ_FILE`, every fuzz case): go's
/// verdict equals algod-rust's.
#[test]
fn peer_meta_headers_decoder_matches_go_on_every_mutated_message() {
    replay::replay_committed_and_fuzz(env!("CARGO_MANIFEST_DIR"), "p2p", verdicts);
}
