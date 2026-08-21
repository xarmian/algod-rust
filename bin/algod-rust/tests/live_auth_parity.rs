//! Live dual-node auth-tier conformance suite (issue #451).
//!
//! Extends `live_go_parity.rs`'s dual-node harness (see that file's module
//! docs for setup) to the full tier x token x header-form matrix, verified
//! against a real go-algorand node rather than just algod-rust's in-process
//! `MockNode` tests (`crates/node/algo-rest-api/tests/integration.rs`).
//!
//! Bring up the harness first:
//!
//! ```text
//! make validate-api-up
//! cargo test --package algod-rust --test live_auth_parity -- --ignored --nocapture
//! make validate-api-down
//! ```
//!
//! # go's auth semantics (reference)
//!
//! `daemon/algod/api/server/lib/middlewares/auth.go`:
//! - OPTIONS is always exempt.
//! - The `X-Algo-API-Token` header is checked first; only if it is *absent
//!   or empty* does go fall back to `Authorization: Bearer <token>` (the
//!   "Bearer" keyword itself is matched case-insensitively via
//!   `strings.EqualFold`, but the token value is not).
//! - Token comparison is exact-byte (`subtle.ConstantTimeCompare`) -- no
//!   trimming, no case-folding of the token value itself.
//! - On failure: `401` with body `InvalidTokenMessage = "Invalid API Token"`.
//!
//! Router wiring (`router.go:83,96`): authenticated (public-tier) routes
//! accept `[adminToken, apiToken]`; admin routes accept `[adminToken]` only.
//! `/health`, `/ready`, `/versions`, `/genesis`, `/swagger.json` carry no
//! auth middleware at all.

/// `docker/localnet-rust/data/algod.token` -- the public API token, shared
/// with every other dev/test harness in this repo (`Makefile`'s
/// `ALGOD_TOKEN`, `docker-compose.*.yml`, etc.).
const DEV_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// A distinct admin token, scoped to *this* harness only (issue #458).
/// `docker/docker-compose.validate-api.yml`'s init script and
/// `Makefile`'s `validate-api-up` target both override
/// `algod.admin.token` to this value on top of the shared genesis data
/// dir, rather than changing the shared `algod.admin.token` file every
/// other harness reads (which still equals [`DEV_TOKEN`], for developer
/// convenience elsewhere). This lets the tests below exercise the case
/// the tier model actually exists for: a genuinely public-only token
/// rejected on an admin-tier route, and a genuinely different admin
/// token accepted there.
const ADMIN_TOKEN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

const GARBAGE_TOKEN: &str = "0000000000000000000000000000000000000000000000000000000000000";

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

/// One auth attempt: `None` means omit the header entirely.
struct AuthHeaders<'a> {
    x_algo_api_token: Option<&'a str>,
    authorization: Option<&'a str>,
}

impl<'a> AuthHeaders<'a> {
    fn none() -> Self {
        Self {
            x_algo_api_token: None,
            authorization: None,
        }
    }
    fn token(t: &'a str) -> Self {
        Self {
            x_algo_api_token: Some(t),
            authorization: None,
        }
    }
    fn bearer(t: &'a str) -> Self {
        Self {
            x_algo_api_token: None,
            authorization: Some(t),
        }
    }
}

async fn request(
    client: &reqwest::Client,
    method: reqwest::Method,
    base: &str,
    path: &str,
    auth: &AuthHeaders<'_>,
) -> reqwest::Response {
    let mut req = client.request(method, format!("{base}{path}"));
    if let Some(t) = auth.x_algo_api_token {
        req = req.header("X-Algo-API-Token", t);
    }
    if let Some(t) = auth.authorization {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    req.send().await.unwrap()
}

/// Assert both nodes agree on status code, and on the error envelope's
/// `message` for 401s (go's fixed `"Invalid API Token"` string).
async fn assert_auth_parity(
    client: &reqwest::Client,
    method: reqwest::Method,
    path: &str,
    auth: AuthHeaders<'_>,
    expected_status: u16,
) {
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let resp = request(client, method.clone(), &base, path, &auth).await;
        assert_eq!(
            resp.status().as_u16(),
            expected_status,
            "{label}: {method} {path} expected {expected_status}"
        );
        if expected_status == 401 {
            let body: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(
                body["message"].as_str(),
                Some("Invalid API Token"),
                "{label}: {method} {path} 401 body must match go's InvalidTokenMessage exactly"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Unauthenticated (common) endpoints
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn unauthenticated_endpoints_succeed_with_any_or_no_token() {
    let c = client();
    for path in [
        "/health",
        "/ready",
        "/versions",
        "/genesis",
        "/swagger.json",
    ] {
        for auth in [
            AuthHeaders::none(),
            AuthHeaders::token(GARBAGE_TOKEN),
            AuthHeaders::token(DEV_TOKEN),
        ] {
            assert_auth_parity(&c, reqwest::Method::GET, path, auth, 200).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Public-tier endpoints
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn public_tier_rejects_missing_and_garbage_tokens() {
    let c = client();
    for path in ["/v2/status", "/v2/transactions/params"] {
        assert_auth_parity(&c, reqwest::Method::GET, path, AuthHeaders::none(), 401).await;
        assert_auth_parity(
            &c,
            reqwest::Method::GET,
            path,
            AuthHeaders::token(GARBAGE_TOKEN),
            401,
        )
        .await;
    }
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn public_tier_accepts_the_shared_token() {
    let c = client();
    for path in ["/v2/status", "/v2/transactions/params"] {
        assert_auth_parity(
            &c,
            reqwest::Method::GET,
            path,
            AuthHeaders::token(DEV_TOKEN),
            200,
        )
        .await;
    }
}

// ---------------------------------------------------------------------------
// Admin-tier endpoints
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn admin_tier_rejects_missing_and_garbage_tokens() {
    let c = client();
    // `/v2/participation` (GET) is admin-tier on both nodes and side-effect
    // free -- avoid `/v2/shutdown` per the issue's own guidance.
    let path = "/v2/participation";
    assert_auth_parity(&c, reqwest::Method::GET, path, AuthHeaders::none(), 401).await;
    assert_auth_parity(
        &c,
        reqwest::Method::GET,
        path,
        AuthHeaders::token(GARBAGE_TOKEN),
        401,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn admin_tier_rejects_a_genuinely_public_only_token() {
    // Issue #458: with a harness-scoped distinct ADMIN_TOKEN, DEV_TOKEN is
    // now a genuinely public-only token on this harness -- the case the
    // tier model exists for and that couldn't be exercised before.
    let c = client();
    assert_auth_parity(
        &c,
        reqwest::Method::GET,
        "/v2/participation",
        AuthHeaders::token(DEV_TOKEN),
        401,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn admin_tier_accepts_the_distinct_admin_token() {
    let c = client();
    assert_auth_parity(
        &c,
        reqwest::Method::GET,
        "/v2/participation",
        AuthHeaders::token(ADMIN_TOKEN),
        200,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Header forms + precedence
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn bearer_header_form_accepted() {
    let c = client();
    assert_auth_parity(
        &c,
        reqwest::Method::GET,
        "/v2/status",
        AuthHeaders::bearer(DEV_TOKEN),
        200,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn x_algo_api_token_header_takes_precedence_over_bearer() {
    // go checks X-Algo-API-Token first; only falls back to Authorization:
    // Bearer when that header is absent/empty (auth.go:72-79). A *valid*
    // X-Algo-API-Token alongside an *invalid* Bearer must still succeed.
    let c = client();
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let resp = client()
            .get(format!("{base}/v2/status"))
            .header("X-Algo-API-Token", DEV_TOKEN)
            .header("Authorization", format!("Bearer {GARBAGE_TOKEN}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "{label}: a valid X-Algo-API-Token must win even with an invalid Bearer present"
        );
    }
    let _ = c;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn invalid_x_algo_api_token_is_not_overridden_by_valid_bearer() {
    // The inverse: an invalid X-Algo-API-Token is *not empty*, so go never
    // falls back to Authorization at all -- a valid Bearer alongside it
    // must NOT rescue the request.
    let c = client();
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let resp = client()
            .get(format!("{base}/v2/status"))
            .header("X-Algo-API-Token", GARBAGE_TOKEN)
            .header("Authorization", format!("Bearer {DEV_TOKEN}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            401,
            "{label}: a non-empty invalid X-Algo-API-Token must not fall back to Bearer"
        );
    }
    let _ = c;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn bearer_keyword_matched_case_insensitively() {
    // go: `strings.EqualFold("Bearer", bearer)` -- the *keyword* is
    // case-insensitive (unlike the token value itself).
    let c = client();
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let resp = client()
            .get(format!("{base}/v2/status"))
            .header("Authorization", format!("bearer {DEV_TOKEN}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "{label}: lowercase \"bearer\" keyword must still be accepted"
        );
    }
    let _ = c;
}

// ---------------------------------------------------------------------------
// Token edge cases -- exact-byte comparison, no trimming
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn token_with_surrounding_whitespace_is_accepted() {
    // Confirmed live: a token padded with spaces is accepted on *both*
    // nodes (200, not 401). This isn't application-level trimming in
    // either implementation's token-comparison code -- RFC 7230 optional
    // whitespace (OWS) around a header *value* is stripped by the HTTP
    // layer itself (go's net/http, and axum/hyper here) before the value
    // ever reaches `subtle.ConstantTimeCompare` / algod-rust's `ct_eq`. An
    // earlier version of this test assumed go's lack of *application-level*
    // trimming meant surrounding whitespace would be rejected; that
    // conflated the HTTP-parsing layer with the token-comparison layer.
    let c = client();
    let padded = format!(" {DEV_TOKEN} ");
    assert_auth_parity(
        &c,
        reqwest::Method::GET,
        "/v2/status",
        AuthHeaders::token(&padded),
        200,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn token_wrong_case_rejected() {
    // The token *value* (unlike the "Bearer" keyword) is compared
    // byte-exact -- an uppercased hex token must not match.
    let c = client();
    let upper = DEV_TOKEN.to_uppercase();
    assert_auth_parity(
        &c,
        reqwest::Method::GET,
        "/v2/status",
        AuthHeaders::token(&upper),
        401,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn empty_x_algo_api_token_header_falls_back_to_bearer() {
    // An empty (present-but-blank) X-Algo-API-Token has len 0, identical to
    // an absent header from go's perspective (`len(providedToken) == 0`) --
    // it must still fall back to a valid Bearer token.
    let c = client();
    for (base, label) in [(go_url(), "go"), (rust_url(), "rust")] {
        let resp = client()
            .get(format!("{base}/v2/status"))
            .header("X-Algo-API-Token", "")
            .header("Authorization", format!("Bearer {DEV_TOKEN}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "{label}: an empty X-Algo-API-Token header must fall back to a valid Bearer token"
        );
    }
    let _ = c;
}

// ---------------------------------------------------------------------------
// Unmatched routes: no auth required, any HTTP method
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires `make validate-api-up`; see module docs"]
async fn unmatched_route_requires_no_auth_for_post_and_delete() {
    let c = client();
    for method in [reqwest::Method::POST, reqwest::Method::DELETE] {
        assert_auth_parity(
            &c,
            method,
            "/v2/this-route-does-not-exist",
            AuthHeaders::none(),
            404,
        )
        .await;
    }
}
