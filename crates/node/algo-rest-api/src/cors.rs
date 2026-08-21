//! CORS support, matching go-algorand's `middlewares.MakeCORS`
//! (`daemon/algod/api/server/lib/middlewares/cors.go`).
//!
//! go wires this as global Echo middleware (`e.Use(middlewares.MakeCORS(...))`,
//! `router.go:98`) — applied to *every* route, including the no-auth ones, and
//! running ahead of any auth check, matching a real browser preflight (which
//! never carries `X-Algo-API-Token`).
//!
//! This is implemented as a hand-written [`middleware::from_fn`] handler
//! rather than via `tower_http::cors::CorsLayer` + `Router::layer`: axum's
//! `Router::layer` wraps each path's registered-method services, but a
//! path's *automatic* `405 Method Not Allowed` response for an unregistered
//! method (e.g. `OPTIONS` on a route that only registers `GET`) is generated
//! by axum's routing internals *before* any `.layer()`-applied middleware
//! gets a chance to run — a well-known axum/tower-http interaction. Since
//! every route in this router registers `OPTIONS` implicitly nowhere,
//! `tower_http::cors::CorsLayer` observably lost its preflight short-circuit
//! to that 405 fallback in practice. Handling `OPTIONS` directly in this
//! middleware — returning the preflight response before ever calling
//! `next.run()` — sidesteps axum's per-route dispatch entirely.

use axum::extract::Request;
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ALLOW,
    VARY,
};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::auth;

/// `Access-Control-Allow-Methods` value, matching go's
/// `AllowMethods: [GET, POST, PUT, DELETE, OPTIONS]` (cors.go).
const ALLOW_METHODS: &str = "GET,POST,PUT,DELETE,OPTIONS";

/// Middleware implementing CORS for the whole router.
///
/// - `OPTIONS` requests are answered directly with go's exact preflight
///   shape (`204 No Content` plus the `Access-Control-Allow-*` headers) and
///   never reach routing/auth.
/// - A non-OPTIONS request that carries an `Origin` header gets
///   `Access-Control-Allow-Origin: *` and `Vary: Origin` added to the
///   response, matching go's simple-request CORS headers.
/// - A request with **no** `Origin` header gets neither — go's
///   `middleware.CORSWithConfig` checks for the header's presence before
///   adding anything at all (it isn't a CORS request otherwise), and an
///   earlier version of this middleware added the headers unconditionally.
///   That was a real, live-verified mismatch (issue #452): every plain
///   same-origin response (no browser, no `Origin` header — the vast
///   majority of algod's actual traffic) incorrectly carried
///   `Access-Control-Allow-Origin: *`/`Vary: Origin` on algod-rust but not
///   on go, and the stray `Vary: Origin` entry could shadow a
///   gzip-negotiated response's `Vary: Accept-Encoding` as the first
///   (client-visible-first) value.
pub async fn cors_layer(request: Request, next: Next) -> Response {
    if request.method() == Method::OPTIONS {
        return preflight_response();
    }

    let has_origin = request.headers().contains_key(axum::http::header::ORIGIN);
    let mut response = next.run(request).await;
    if has_origin {
        let headers = response.headers_mut();
        headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, wildcard());
        headers.append(VARY, HeaderValue::from_static("Origin"));
    }
    response
}

/// The exact CORS preflight response go-algorand's Echo middleware produces
/// for an `OPTIONS` request (verified live against go-algorand
/// v4.5.1-stable): `204 No Content` with `Access-Control-Allow-Origin: *`,
/// `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, and a
/// multi-value `Vary` header.
fn preflight_response() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    let headers = response.headers_mut();
    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, wildcard());
    headers.insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static(ALLOW_METHODS),
    );
    headers.insert(ACCESS_CONTROL_ALLOW_HEADERS, allow_headers_value());
    // axum's routing internals unconditionally add an `Allow` header — the
    // *route's actual registered methods* (e.g. `GET,HEAD` for a GET-only
    // route) — to any response that doesn't already set one, regardless of
    // what a `.layer()`-applied middleware already built
    // (`axum::routing::route::RouteFuture::poll`, `set_allow_header`, which
    // only skips when the header is already present). Since this middleware
    // is global rather than per-route, it cannot know each route's exact
    // method set the way go's per-route Echo registration can; setting the
    // same method list as `Access-Control-Allow-Methods` here at least keeps
    // the header non-misleading rather than reporting axum's route-specific
    // (and CORS-irrelevant) `GET,HEAD` default.
    headers.insert(ALLOW, HeaderValue::from_static(ALLOW_METHODS));
    headers.append(VARY, HeaderValue::from_static("Origin"));
    headers.append(
        VARY,
        HeaderValue::from_static("Access-Control-Request-Method"),
    );
    headers.append(
        VARY,
        HeaderValue::from_static("Access-Control-Request-Headers"),
    );
    response
}

fn wildcard() -> HeaderValue {
    HeaderValue::from_static("*")
}

/// `Access-Control-Allow-Headers` value: the token header plus
/// `Content-Type`, matching go's `AllowHeaders: [TokenHeader, "Content-Type"]`
/// (cors.go).
fn allow_headers_value() -> HeaderValue {
    HeaderValue::from_str(&format!("{},Content-Type", auth::API_TOKEN_HEADER))
        .expect("API_TOKEN_HEADER is a valid header value")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    fn test_router() -> Router {
        Router::new()
            .route("/x", get(|| async { "hi" }))
            .layer(axum::middleware::from_fn(cors_layer))
    }

    #[tokio::test]
    async fn options_returns_204_with_full_preflight_headers() {
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/x")
                    .header("Origin", "https://example.com")
                    .header("Access-Control-Request-Method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let headers = resp.headers();
        assert_eq!(headers.get(ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), "*");
        assert_eq!(
            headers.get(ACCESS_CONTROL_ALLOW_METHODS).unwrap(),
            ALLOW_METHODS
        );
        let allow_headers = headers
            .get(ACCESS_CONTROL_ALLOW_HEADERS)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(allow_headers.contains("X-Algo-API-Token"));
        assert!(allow_headers.contains("Content-Type"));

        assert_eq!(
            headers.get(ALLOW).unwrap(),
            ALLOW_METHODS,
            "must not leak axum's route-specific default Allow header"
        );

        let vary_values: Vec<&str> = headers
            .get_all(VARY)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            vary_values,
            vec![
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers"
            ]
        );

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        assert!(body.is_empty(), "204 must have an empty body");
    }

    async fn panicking_handler() -> &'static str {
        panic!("handler must not run for an OPTIONS preflight");
    }

    #[tokio::test]
    async fn options_never_reaches_the_handler() {
        // A route that would panic if invoked, proving OPTIONS never calls next().
        let router = Router::new()
            .route("/panics", get(panicking_handler))
            .layer(axum::middleware::from_fn(cors_layer));

        let resp = router
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/panics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn simple_get_carries_wildcard_origin_and_vary() {
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/x")
                    .header("Origin", "https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "*"
        );
        assert_eq!(resp.headers().get(VARY).unwrap(), "Origin");
    }

    #[tokio::test]
    async fn simple_get_without_origin_carries_no_cors_headers() {
        // go's middleware.CORSWithConfig checks for the Origin header's
        // presence before adding anything -- a plain same-origin request
        // (no browser, no Origin header at all) must not gain
        // Access-Control-Allow-Origin/Vary: Origin (issue #452).
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/x")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
        assert!(resp.headers().get(VARY).is_none());
    }
}
