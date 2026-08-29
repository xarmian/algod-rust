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

//! Live dual-node response header conformance suite (issue #452).
//!
//! Extends `live_go_parity.rs`'s dual-node harness (see that file's module
//! docs for setup) to the full response-header surface. PR #446 verified
//! two header behaviors live (gzip `Content-Encoding`, CORS preflight); this
//! file covers the rest: `Content-Type` exactness, CORS on *simple*
//! (non-preflight) requests, `Vary`, gzip negotiation edge cases, error
//! response headers, and `Content-Length`/chunked framing.
//!
//! Bring up the harness first:
//!
//! ```text
//! make validate-api-up
//! cargo test --package algod-rust --test live_headers_parity -- --ignored --nocapture
//! make validate-api-down
//! ```
//!
//! # Allowlist
//!
//! Headers that are legitimately implementation-specific and never expected
//! to match are excluded from the "every other header must match" checks:
//! `date` (wall-clock timestamp), `server` (neither node sets an
//! identifying value today, but exempted defensively), and
//! `x-algod-round`-style headers if either implementation ever adds one
//! (none currently do). `content-length` is checked for *presence*
//! agreement (both framed the same way -- fixed-length vs chunked) rather
//! than exact byte-count equality, since even a byte-identical JSON body
//! can differ in length once gzip-negotiated (compressed size is never
//! expected to match exactly between two independent gzip implementations
//! or the same implementation at a different compression level).

use std::collections::BTreeSet;

const DEV_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Headers excluded from the "every other header name must match" check.
/// See the module doc comment for why each is here.
const ALLOWLISTED_HEADERS: &[&str] = &["date", "server"];

fn go_url() -> String {
    std::env::var("ALGOD_GO_URL").unwrap_or_else(|_| "http://127.0.0.1:4001".to_string())
}

fn rust_url() -> String {
    std::env::var("ALGOD_RUST_URL").unwrap_or_else(|_| "http://127.0.0.1:4002".to_string())
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .build()
        .expect("build reqwest client")
}

/// Header names (lowercased), excluding the allowlist.
fn header_name_set(resp: &reqwest::Response) -> BTreeSet<String> {
    resp.headers()
        .keys()
        .map(|k| k.as_str().to_ascii_lowercase())
        .filter(|k| !ALLOWLISTED_HEADERS.contains(&k.as_str()))
        .collect()
}

fn header_value<'a>(resp: &'a reqwest::Response, name: &str) -> Option<&'a str> {
    resp.headers().get(name).and_then(|v| v.to_str().ok())
}

/// Compare the (allowlist-filtered) header *name* set and every named
/// header's *value* between the two nodes' responses, reporting every
/// mismatch rather than stopping at the first.
fn diff_headers(label: &str, go: &reqwest::Response, rust: &reqwest::Response) -> Vec<String> {
    let mut mismatches = Vec::new();
    let go_names = header_name_set(go);
    let rust_names = header_name_set(rust);
    for name in go_names.symmetric_difference(&rust_names) {
        let go_has = go_names.contains(name);
        mismatches.push(format!(
            "{label}: header {name:?} present only on {}",
            if go_has { "go" } else { "rust" }
        ));
    }
    for name in go_names.intersection(&rust_names) {
        // content-length's exact byte count is excluded (see module docs);
        // presence-agreement is already covered by the name-set diff above.
        if name == "content-length" {
            continue;
        }
        let gv = header_value(go, name);
        let rv = header_value(rust, name);
        if gv != rv {
            mismatches.push(format!("{label}: header {name:?} go={gv:?} rust={rv:?}"));
        }
    }
    mismatches
}

async fn get(client: &reqwest::Client, base: &str, path: &str) -> reqwest::Response {
    client
        .get(format!("{base}{path}"))
        .header("X-Algo-API-Token", DEV_TOKEN)
        .send()
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------
// Content-Type exactness across endpoint categories
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn content_type_matches_across_endpoint_categories() {
    let c = client();
    // One representative endpoint per category the issue names: common,
    // accounts, blocks, transactions, teal, deltas. (participation/admin is
    // covered by `error_response_headers_match` below via its 401 path,
    // since a side-effect-free *successful* admin request isn't available
    // without real participation keys.)
    let paths = [
        "/health",                 // common (plain text/no body)
        "/genesis",                // common (JSON)
        "/v2/status",              // common (JSON)
        "/v2/ledger/supply",       // ledger (JSON)
        "/v2/blocks/0",            // blocks (JSON)
        "/v2/transactions/params", // transactions (JSON)
    ];
    for path in paths {
        let go = get(&c, &go_url(), path).await;
        let rust = get(&c, &rust_url(), path).await;
        let go_ct = header_value(&go, "content-type").map(str::to_string);
        let rust_ct = header_value(&rust, "content-type").map(str::to_string);
        assert_eq!(
            go_ct, rust_ct,
            "{path}: Content-Type must match exactly (including any charset suffix)"
        );
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn content_type_matches_for_msgpack_responses() {
    let c = client();
    let go = get(&c, &go_url(), "/v2/status").await;
    // /v2/status doesn't take format=msgpack; use an endpoint that does.
    let fee_sink = "AOVDCP4FEMVDRM6XDX6ERJDHLY6TDW42MRKCVLX2PAZZQZICS7M2EZWWAU";
    let go_mp = get(
        &c,
        &go_url(),
        &format!("/v2/accounts/{fee_sink}?format=msgpack"),
    )
    .await;
    let rust_mp = get(
        &c,
        &rust_url(),
        &format!("/v2/accounts/{fee_sink}?format=msgpack"),
    )
    .await;
    assert_eq!(
        header_value(&go_mp, "content-type"),
        header_value(&rust_mp, "content-type"),
    );
    let _ = go;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn teal_compile_content_type_matches() {
    let c = client();
    let program = "#pragma version 6\nint 1\nreturn\n";
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let resp = c
            .post(format!("{base}/v2/teal/compile"))
            .header("X-Algo-API-Token", DEV_TOKEN)
            .header("Content-Type", "text/plain")
            .body(program)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "{label}: teal/compile of a valid program must succeed"
        );
        assert_eq!(
            header_value(&resp, "content-type"),
            Some("application/json"),
            "{label}: teal/compile response Content-Type"
        );
    }
}

// ---------------------------------------------------------------------------
// Full header-set diff per category (success paths)
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn full_header_set_matches_per_category() {
    let c = client();
    let paths = [
        "/health",
        "/genesis",
        "/v2/status",
        "/v2/ledger/supply",
        "/v2/blocks/0",
        "/v2/transactions/params",
    ];
    let mut all_mismatches = Vec::new();
    for path in paths {
        let go = get(&c, &go_url(), path).await;
        let rust = get(&c, &rust_url(), path).await;
        all_mismatches.extend(diff_headers(path, &go, &rust));
    }
    assert!(
        all_mismatches.is_empty(),
        "header mismatches:\n{}",
        all_mismatches.join("\n")
    );
}

// ---------------------------------------------------------------------------
// CORS on simple (non-preflight) requests
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn cors_headers_present_on_simple_get_with_origin() {
    let c = client();
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let resp = c
            .get(format!("{base}/v2/status"))
            .header("X-Algo-API-Token", DEV_TOKEN)
            .header("Origin", "https://example.com")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "{label}: simple GET with Origin");
        assert_eq!(
            header_value(&resp, "access-control-allow-origin"),
            Some("*"),
            "{label}: Access-Control-Allow-Origin must be present on a simple request too, not just preflight"
        );
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn cors_headers_present_on_simple_post_with_origin() {
    let c = client();
    let garbage_body = b"\xff\xff not a valid txn group";
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        // A malformed submission is fine here -- only the CORS headers on
        // the (error) response are under test.
        let resp = c
            .post(format!("{base}/v2/transactions"))
            .header("X-Algo-API-Token", DEV_TOKEN)
            .header("Origin", "https://example.com")
            .header("Content-Type", "application/x-binary")
            .body(garbage_body.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(
            header_value(&resp, "access-control-allow-origin"),
            Some("*"),
            "{label}: Access-Control-Allow-Origin must be present on a simple POST (even an erroring one)"
        );
    }
}

// ---------------------------------------------------------------------------
// gzip negotiation edge cases
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn gzip_not_negotiated_with_identity_only() {
    let c = client();
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let resp = c
            .get(format!("{base}/v2/status"))
            .header("X-Algo-API-Token", DEV_TOKEN)
            .header("Accept-Encoding", "identity")
            .send()
            .await
            .unwrap();
        assert_eq!(
            header_value(&resp, "content-encoding"),
            None,
            "{label}: Accept-Encoding: identity must not produce a gzip response"
        );
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn gzip_ignores_quality_value_matching_go() {
    // go's Echo Gzip middleware does *not* parse Accept-Encoding quality
    // values at all -- it compresses whenever the string "gzip" appears
    // anywhere in the header, "q=0" included. This is arguably a bug in
    // go's middleware (RFC 7231 ss5.3.4 says q=0 means "not acceptable"),
    // but conformance means matching it: issue #460 added
    // `normalize_accept_encoding_for_gzip_substring_match`, a request
    // middleware that rewrites any Accept-Encoding value containing the
    // substring "gzip" to a bare "gzip" before `tower_http::CompressionLayer`
    // (which does correct, spec-compliant negotiation on its own) ever sees
    // it -- so both nodes now compress this request identically.
    let c = client();
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let resp = c
            .get(format!("{base}/v2/status"))
            .header("X-Algo-API-Token", DEV_TOKEN)
            .header("Accept-Encoding", "gzip;q=0, identity")
            .send()
            .await
            .unwrap();
        assert_eq!(
            header_value(&resp, "content-encoding"),
            Some("gzip"),
            "{label}: Accept-Encoding: gzip;q=0 must still be compressed (quality values are not parsed)"
        );
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn unknown_encodings_not_negotiated() {
    // go's Echo Gzip middleware only ever negotiates gzip -- br/zstd must
    // never appear in Content-Encoding even if requested.
    let c = client();
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let resp = c
            .get(format!("{base}/v2/status"))
            .header("X-Algo-API-Token", DEV_TOKEN)
            .header("Accept-Encoding", "br, zstd")
            .send()
            .await
            .unwrap();
        let encoding = header_value(&resp, "content-encoding");
        assert!(
            encoding.is_none() || encoding == Some("gzip"),
            "{label}: only gzip may ever be negotiated, got {encoding:?}"
        );
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn vary_header_on_gzip_negotiated_response() {
    let c = client();
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let resp = c
            .get(format!("{base}/v2/status"))
            .header("X-Algo-API-Token", DEV_TOKEN)
            .header("Accept-Encoding", "gzip")
            .send()
            .await
            .unwrap();
        assert_eq!(
            header_value(&resp, "content-encoding"),
            Some("gzip"),
            "{label}: sanity check -- this request must actually negotiate gzip"
        );
        let vary = header_value(&resp, "vary");
        assert!(
            vary.map(|v| v.to_ascii_lowercase().contains("accept-encoding"))
                .unwrap_or(false),
            "{label}: a gzip-negotiated response must carry Vary: Accept-Encoding, got {vary:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Content-Length / chunked framing
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn framing_matches_uncompressed() {
    let c = client();
    let go = get(&c, &go_url(), "/v2/status").await;
    let rust = get(&c, &rust_url(), "/v2/status").await;
    // Both must agree on whether the response is framed with a
    // Content-Length header or Transfer-Encoding: chunked.
    let go_framed = header_value(&go, "content-length").is_some();
    let rust_framed = header_value(&rust, "content-length").is_some();
    assert_eq!(
        go_framed, rust_framed,
        "uncompressed /v2/status must use the same framing strategy on both nodes"
    );
}

// ---------------------------------------------------------------------------
// Error response headers
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn error_response_headers_match() {
    let c = client();
    let mut all_mismatches = Vec::new();

    // 401: missing token on a public-tier endpoint.
    {
        let go = c
            .get(format!("{}/v2/status", go_url()))
            .send()
            .await
            .unwrap();
        let rust = c
            .get(format!("{}/v2/status", rust_url()))
            .send()
            .await
            .unwrap();
        assert_eq!(go.status(), 401);
        assert_eq!(rust.status(), 401);
        all_mismatches.extend(diff_headers("401 /v2/status", &go, &rust));
    }

    // 404: unmatched route (no auth required).
    {
        let go = c
            .get(format!("{}/v2/this-route-does-not-exist", go_url()))
            .send()
            .await
            .unwrap();
        let rust = c
            .get(format!("{}/v2/this-route-does-not-exist", rust_url()))
            .send()
            .await
            .unwrap();
        assert_eq!(go.status(), 404);
        assert_eq!(rust.status(), 404);
        all_mismatches.extend(diff_headers("404 unmatched route", &go, &rust));
    }

    // 400: invalid format value.
    {
        let go = get(&c, &go_url(), "/v2/status/wait-for-block-after/not-a-round").await;
        let rust = get(
            &c,
            &rust_url(),
            "/v2/status/wait-for-block-after/not-a-round",
        )
        .await;
        assert_eq!(go.status(), 400);
        assert_eq!(rust.status(), 400);
        all_mismatches.extend(diff_headers("400 invalid round", &go, &rust));
    }

    assert!(
        all_mismatches.is_empty(),
        "error response header mismatches:\n{}",
        all_mismatches.join("\n")
    );
}
