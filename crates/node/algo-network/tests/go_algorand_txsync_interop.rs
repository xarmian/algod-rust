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

//! Live interop check (issue #792) against a **real go-algorand
//! `v5.0.0-stable` binary**'s tx-sync HTTP endpoint.
//!
//! `#[ignore]`d by default: it needs a running go-algorand node reachable
//! over the network, which this crate's default `cargo test` run cannot
//! assume (no such node is started in CI for this endpoint). Run manually
//! after standing one up.
//!
//! ## How this was verified for PR #800
//!
//! A minimal single-node go-algorand `v5.0.0-stable` network was created
//! and started via the real `algorand/algod:5.0.0-stable` Docker image
//! (the same image `ops/mixed-cluster/` uses), with its sole wallet
//! offline (`"Online": false`) so the chain never leaves round 0 and a
//! submitted transaction stays in the pending pool indefinitely — no race
//! against block confirmation:
//!
//! ```text
//! goal network create -n issue792net -r ./netroot -t template.json   # 1 relay, 1 offline wallet
//! # overlay Node1/config.json: NetAddress=0.0.0.0:4161, DNSBootstrapID=""
//! docker run -d --name issue792-node1 \
//!   -e ALGORAND_DATA=/algod/data -e ALGOD_PORT=8080 \
//!   -e TOKEN=... -e ADMIN_TOKEN=... \
//!   -p 127.0.0.1:14001:8080 -p 127.0.0.1:14161:4161 \
//!   -v ./netroot/Node1:/algod/data \
//!   algorand/algod:5.0.0-stable
//! docker exec -e ALGORAND_DATA=/algod/data issue792-node1 \
//!   goal clerk send -f <addr> -t <addr> -a 1000 --fee 1000 -n live-verify
//! # -> "Transaction <TXID> still pending as of round 0" (stays pending forever)
//! ```
//!
//! Then, with this crate's actual (compiled) [`algo_network::BloomFilter`]
//! and the go-real wire shapes this PR implements:
//!
//! ```text
//! GO_ALGOD_TXSYNC_ADDR=127.0.0.1:14161 \
//! GO_ALGOD_GENESIS_ID=issue792net-v1 \
//! GO_ALGOD_EXPECT_TXID_B32=LHRFQUIJJXNKRWYSRCO2MJ3ITGQQMDDR4AVDFGIWUZWLM6RBFBQA \
//!   cargo test -p algo-network --test go_algorand_txsync_interop -- --ignored --nocapture
//! ```
//!
//! passed: the real go-algorand node accepted the POST at its real path
//! (`/v1/{genesisID}/txsync`, form-urlencoded `bf` field), answered `200
//! application/x-algorand-ptx-v1`, and its body decoded (via this crate's
//! own canonical msgpack path) to exactly one `SignedTransaction` whose
//! ID matched the just-submitted `LHRFQUIJJXNKRWYSRCO2MJ3ITGQQMDDR4AVDFGIWUZWLM6RBFBQA`.
//!
//! Set the three `GO_ALGOD_*` env vars below to re-run against a fresh
//! node (the txid check is skipped if `GO_ALGOD_EXPECT_TXID_B32` is
//! unset, so this also works as a bare reachability/shape check).

use algo_network::BloomFilter;
use algo_types::SignedTransaction;

/// Algorand's base32 alphabet (RFC 4648 without padding) — used to decode
/// a human-readable txid (`goal clerk send`'s printed `transaction ID:`)
/// back to the raw bytes `SignedTransaction::txn`'s `ID()` produces.
fn base32_decode_no_pad(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits: u64 = 0;
    let mut bit_count = 0u32;
    let mut out = Vec::new();
    for c in s.bytes() {
        let val = ALPHABET.iter().position(|&a| a == c.to_ascii_uppercase())? as u64;
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push((bits >> bit_count) as u8);
        }
    }
    Some(out)
}

#[tokio::test]
#[ignore = "requires a real go-algorand v5.0.0-stable node reachable at GO_ALGOD_TXSYNC_ADDR -- see module doc"]
async fn real_go_algorand_txsync_endpoint_answers_our_bloom_filter_request() {
    let addr = std::env::var("GO_ALGOD_TXSYNC_ADDR").unwrap_or_else(|_| "127.0.0.1:14161".into());
    let genesis_id =
        std::env::var("GO_ALGOD_GENESIS_ID").unwrap_or_else(|_| "issue792net-v1".into());
    let expect_txid_b32 = std::env::var("GO_ALGOD_EXPECT_TXID_B32").ok();

    // Empty pending set -> a filter matching nothing, so the real node
    // reports every one of its own pending transactions as "missing".
    let (size_bits, num_hashes) = BloomFilter::optimal(0, 0.01);
    let filter = BloomFilter::new(size_bits, num_hashes, 0);
    let bloom_param = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE,
        filter.marshal_binary(),
    );
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("bf", &bloom_param)
        .finish();

    let url = format!("http://{addr}/v1/{genesis_id}/txsync");
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .unwrap_or_else(|e| panic!("request to real go-algorand node at {url} failed: {e}"));

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "real go-algorand node rejected our go-shaped tx-sync request"
    );
    assert_eq!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/x-algorand-ptx-v1"),
    );

    let bytes = resp.bytes().await.expect("read response body");
    let txns: Vec<SignedTransaction> =
        rmp_serde::from_slice(&bytes).expect("decode go's real canonical msgpack array");

    println!(
        "real go-algorand node returned {} pending transaction(s)",
        txns.len()
    );

    if let Some(expect_b32) = expect_txid_b32 {
        let expect_raw =
            base32_decode_no_pad(&expect_b32).expect("GO_ALGOD_EXPECT_TXID_B32 is valid base32");
        let found = txns.iter().any(|stx| {
            let id = algo_codec::compute_txn_id(&stx.txn);
            // go's txid string is the base32 encoding of the digest,
            // i.e. compare the raw digest bytes.
            id.as_bytes().as_slice() == &expect_raw[..32]
        });
        assert!(
            found,
            "expected txid {expect_b32} not found among {} returned transaction(s)",
            txns.len()
        );
    }
}
