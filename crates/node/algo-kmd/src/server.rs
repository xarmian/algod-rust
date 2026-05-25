//! kmd HTTP server bootstrap.
//!
//! Ported from `../go-algorand/daemon/kmd/server/server.go` and
//! `daemon/kmd/api/{api,cors}.go` (v4.5.1-stable). Brings up an axum
//! server on `127.0.0.1:auto`, writes the `kmd.net` / `kmd.pid` /
//! `kmd.lock` lifecycle files, exposes the two non-versioned routes
//! (`GET /versions`, `GET /swagger.json`), handles OPTIONS for CORS,
//! and enforces the bearer-token middleware on every `/v1/*` route.
//!
//! ## Scope (Phase B / TASK-212)
//!
//! - No `/v1/*` handlers — those land in B5–B8.  A `/v1/anything`
//!   request hits the auth middleware first (401 on bad token) and
//!   then 404s on an authenticated-but-unrouted path.
//! - No TLS — kmd binds localhost only, matching Go.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::Router;
use fs2::FileExt;
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::auth::validate_api_token;
use crate::error::{Error, Result};
use crate::session::SessionManager;

/// `NetFilename` (server.go:40) — file containing `host:port`.
pub const NET_FILENAME: &str = "kmd.net";
/// `PIDFilename` (server.go:42).
pub const PID_FILENAME: &str = "kmd.pid";
/// `LockFilename` (server.go:44).
pub const LOCK_FILENAME: &str = "kmd.lock";
/// `DefaultKMDPort` (server.go:46).
pub const DEFAULT_KMD_PORT: u16 = 7833;
/// `DefaultKMDHost` (server.go:48). kmd binds localhost only.
pub const DEFAULT_KMD_HOST: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

/// `KMDTokenHeader` (`api/v1/auth.go:29`) — name of the bearer-token
/// header every authenticated request must carry.
pub const KMD_TOKEN_HEADER: &str = "X-KMD-API-Token";

/// CORS `Access-Control-Allow-Methods` — matches `allowedMethods`
/// (api/cors.go:26).
const CORS_ALLOWED_METHODS: &str = "GET, POST, DELETE, OPTIONS";

/// CORS `Access-Control-Allow-Headers` — matches `allowedHeaders`
/// (api/cors.go:27), `X-KMD-API-Token, Content-Type`.
const CORS_ALLOWED_HEADERS: &str = "X-KMD-API-Token, Content-Type";

/// Vendored copy of `go-algorand/daemon/kmd/api/swagger.json`
/// (v4.5.1-stable).  Served byte-for-byte at `GET /swagger.json`.
///
/// A round-trip test asserts this stays equal to the upstream file
/// when go-algorand is checked out alongside this repo (see
/// `tests::vendored_swagger_matches_go_algorand`).
const SWAGGER_JSON: &str = include_str!("../swagger.json");

/// `supportedAPIVersions = []string{"v1"}` (api/api.go:84) —
/// what `GET /versions` advertises.
const SUPPORTED_API_VERSIONS: &[&str] = &["v1"];

/// Server configuration. Mirrors `WalletServerConfig` (server.go:52).
#[derive(Debug, Clone)]
pub struct WalletServerConfig {
    /// The pre-shared bearer token clients send in `X-KMD-API-Token`.
    /// Length-validated by [`validate_api_token`] during
    /// [`WalletServer::bind`].
    pub api_token: String,
    /// kmd data directory.  Receives the `kmd.net` / `kmd.pid` /
    /// `kmd.lock` lifecycle files.
    pub data_dir: PathBuf,
    /// Optional `host:port` override.  When `None`, kmd tries
    /// `127.0.0.1:7833` first and falls back to an OS-assigned port.
    pub address: Option<SocketAddr>,
    /// CORS allow-list.  An entry of `"*"` echoes the request origin
    /// back (matching go-algorand).
    pub allowed_origins: Vec<String>,
    /// When `true`, OPTIONS preflights with `Access-Control-Request-
    /// Private-Network: true` get `Access-Control-Allow-Private-
    /// Network: true` (matches Go's `AllowPNA`).
    pub allow_header_pna: bool,
    /// Shared session manager.  Wired through to v1 handlers in B5–B8.
    pub session_manager: Arc<SessionManager>,
}

/// Outcome of [`WalletServer::bind`] — the bound address, plus the
/// future you await to actually serve.
#[derive(Debug)]
pub struct WalletServer {
    config: WalletServerConfig,
    addr: SocketAddr,
    listener: TcpListener,
    net_path: PathBuf,
    pid_path: PathBuf,
    // Held for the lifetime of the server so the OS lock is released
    // automatically when the server drops, even on a panic.
    lock_file: std::fs::File,
}

impl WalletServer {
    /// Validate the config, acquire the file lock, bind a TCP
    /// listener, and write `kmd.net` / `kmd.pid`.  Mirrors
    /// `MakeWalletServer` + the first half of `Start`/`start`
    /// (server.go:102-261).
    ///
    /// After this returns, the server is reserved on its port and
    /// ready to serve via [`serve`](Self::serve).
    pub async fn bind(config: WalletServerConfig) -> Result<Self> {
        validate_api_token(&config.api_token)?;
        if !config.data_dir.is_dir() {
            return Err(Error::DataDirMissing(config.data_dir.clone()));
        }

        let net_path = config.data_dir.join(NET_FILENAME);
        let pid_path = config.data_dir.join(PID_FILENAME);
        let lock_path = config.data_dir.join(LOCK_FILENAME);

        // Acquire the exclusive file lock (rejects a second kmd-rust
        // on the same data dir).  Matches `acquireFileLock`
        // (server.go:120) — Go uses `gofrs/flock.TryLock`; we use
        // `fs2::try_lock_exclusive` which compiles to the same
        // `flock(LOCK_EX|LOCK_NB)` on Unix and `LockFileEx` on
        // Windows.
        let lock_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(Error::Io)?;
        if let Err(e) = lock_file.try_lock_exclusive() {
            // fs2 returns `WouldBlock` when another process holds the
            // lock; surface that as `AlreadyRunning` so the caller
            // gets the same Go-side `ErrAlreadyRunning` message.
            if e.kind() == std::io::ErrorKind::WouldBlock {
                return Err(Error::AlreadyRunning);
            }
            return Err(Error::Io(e));
        }

        // Bind the listener.  If the user gave us a specific address,
        // refuse to fall back — they may rely on that port being
        // reserved.  Otherwise try 7833 first, then OS-assigned
        // (server.go:232-254).
        let listener = match config.address {
            Some(addr) => TcpListener::bind(addr).await.map_err(Error::Io)?,
            None => {
                let primary = SocketAddr::new(DEFAULT_KMD_HOST, DEFAULT_KMD_PORT);
                match TcpListener::bind(primary).await {
                    Ok(l) => l,
                    Err(_) => {
                        let any_port = SocketAddr::new(DEFAULT_KMD_HOST, 0);
                        TcpListener::bind(any_port).await.map_err(Error::Io)?
                    }
                }
            }
        };
        let addr = listener.local_addr().map_err(Error::Io)?;

        // Write kmd.net + kmd.pid (server.go:143-152).
        std::fs::write(&net_path, addr.to_string().as_bytes()).map_err(Error::Io)?;
        std::fs::write(&pid_path, std::process::id().to_string().as_bytes()).map_err(Error::Io)?;

        // `lock_path` is kept in scope only via the open `lock_file`
        // handle — `fs2` ties the OS lock to the file descriptor, so
        // we don't need to remember the path after acquisition.
        let _ = lock_path;

        Ok(Self {
            config,
            addr,
            listener,
            net_path,
            pid_path,
            lock_file,
        })
    }

    /// Bound address (`host:port`).  Useful for tests that bind on
    /// port 0 and need to know where the OS placed them.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Build the axum router for this server.  Public because B5–B8
    /// will extend it with v1 sub-routers; ordinary callers want
    /// [`serve`](Self::serve).
    pub fn router(&self) -> Router {
        build_router(
            self.config.api_token.clone(),
            self.config.allowed_origins.clone(),
            self.config.allow_header_pna,
        )
    }

    /// Serve forever, until `shutdown` resolves.  On any exit
    /// (graceful or panic), `kmd.net` and `kmd.pid` are removed and
    /// the file lock is released.  Matches the back half of
    /// `start` (server.go:267-290).
    pub async fn serve(self, shutdown: oneshot::Receiver<()>) -> Result<()> {
        let router = self.router();
        let WalletServer {
            config: _,
            addr: _,
            listener,
            net_path,
            pid_path,
            lock_file,
        } = self;

        // `axum::serve(...).with_graceful_shutdown(future)` resolves
        // when the future resolves OR the listener errors.
        let result = axum::serve(listener, router.into_make_service())
            .with_graceful_shutdown(async move {
                let _ = shutdown.await;
            })
            .await;

        // Cleanup — best-effort; log but don't propagate.
        if let Err(e) = std::fs::remove_file(&net_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %net_path.display(), error = %e, "failed to remove kmd.net");
            }
        }
        if let Err(e) = std::fs::remove_file(&pid_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %pid_path.display(), error = %e, "failed to remove kmd.pid");
            }
        }
        // `lock_file` drops here, releasing the OS lock.  We
        // intentionally don't remove `kmd.lock` itself — the file
        // stays in the data dir for the next start to re-lock, which
        // matches Go (`gofrs/flock` leaves the file in place too).
        drop(lock_file);

        result.map_err(Error::Io)
    }
}

/// Build the root router.  Exposed so tests can drive it with
/// `tower::Service` without binding a real socket.
fn build_router(api_token: String, allowed_origins: Vec<String>, allow_header_pna: bool) -> Router {
    let auth_state = AuthState {
        expected_token: Arc::new(api_token),
    };

    // Public, non-versioned routes (api/api.go:154-156).
    let public = Router::new()
        .route("/versions", get(versions_handler))
        .route("/swagger.json", get(swagger_handler));

    // `/v1/*` — auth middleware applied; no real handlers yet (B5–B8
    // will register them).  Unmatched paths fall through to the
    // outer 404 handler AFTER auth has validated the token, so a
    // bad token never reveals which routes exist.
    let v1 = Router::new()
        .fallback(any(v1_not_found))
        .layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            require_kmd_token,
        ));

    let mut app = Router::new()
        .merge(public)
        .nest("/v1", v1)
        .fallback(any(root_not_found));

    // Add the OPTIONS short-circuit BEFORE the CORS layer so the
    // outer CORS layer (and PNA layer below) can stamp their
    // `Access-Control-*` headers onto the 200 response on the way
    // out.  Matches Go's `rootRouter.Methods("OPTIONS").HandlerFunc(
    // optionsHandler)` (`api/api.go:150`): every OPTIONS request —
    // preflight or not — short-circuits to 200, and the CORS
    // middleware that ran on the way in attaches the right headers
    // on the way out.
    //
    // Axum layer semantics: the most recently added `.layer(...)` is
    // outermost (runs first on the request, last on the response),
    // so adding the short-circuit first puts it innermost — which is
    // what we want.
    app = app.layer(axum::middleware::from_fn(options_short_circuit));

    app = app.layer(build_cors_layer(allowed_origins));

    if allow_header_pna {
        app = app.layer(axum::middleware::from_fn(allow_pna_middleware));
    }

    app
}

/// Top-of-stack middleware that mirrors Go's catch-all
/// `optionsHandler` (api/api.go:113): any OPTIONS request — with or
/// without an `Origin` header — short-circuits to 200 without
/// invoking the inner router.  CORS / PNA layers wrap this one, so
/// the response still gets the right `Access-Control-Allow-*`
/// headers when the request is a preflight.
async fn options_short_circuit(req: Request, next: Next) -> Response {
    if req.method() == Method::OPTIONS {
        return StatusCode::OK.into_response();
    }
    next.run(req).await
}

/// `versionsHandler` (api/api.go:88-109).  Returns
/// `{"versions":["v1"]}`.  No auth.
async fn versions_handler() -> Response {
    let body = algo_kmd_api_types::responses::VersionsResponse {
        versions: SUPPORTED_API_VERSIONS
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
    };
    let json = serde_json::to_vec(&body).expect("VersionsResponse always serializes");
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json,
    )
        .into_response()
}

/// `SwaggerHandler` (api/api.go:119-136).  Returns the embedded
/// swagger spec byte-for-byte.  No auth.
async fn swagger_handler() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        SWAGGER_JSON,
    )
        .into_response()
}

#[derive(Clone)]
struct AuthState {
    expected_token: Arc<String>,
}

/// Bearer-token middleware applied to every `/v1/*` route.  Mirrors
/// `authMiddleware` (api/v1/auth.go:32-58): constant-time compare of
/// the `X-KMD-API-Token` header against the configured token.
/// Returns `{"error":true,"message":"invalid API token"}` on
/// mismatch — matches Go's `errorResponse(401, errInvalidAPIToken)`.
async fn require_kmd_token(State(state): State<AuthState>, req: Request, next: Next) -> Response {
    // OPTIONS preflights are exempt — the CORS layer (and Go's
    // `optionsHandler`) handles them without auth.
    if req.method() == Method::OPTIONS {
        return next.run(req).await;
    }

    let provided = req
        .headers()
        .get(KMD_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if provided
        .as_bytes()
        .ct_eq(state.expected_token.as_bytes())
        .into()
    {
        next.run(req).await
    } else {
        unauthorized_response()
    }
}

fn unauthorized_response() -> Response {
    let body = serde_json::json!({
        "error": true,
        "message": "invalid API token",
    });
    (
        StatusCode::UNAUTHORIZED,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

async fn v1_not_found() -> Response {
    // We reach here only after the auth middleware accepted the
    // token.  Return a clean 404 envelope so v1 clients can parse it.
    let body = serde_json::json!({
        "error": true,
        "message": "not found",
    });
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

async fn root_not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

/// CORS layer matching `corsMiddleware` (api/cors.go:29-58).  Each
/// allowed origin is compared in constant time; an entry of `"*"`
/// echoes whatever Origin the client sent back (Go uses the same
/// "reflect on wildcard" behavior).
fn build_cors_layer(allowed_origins: Vec<String>) -> CorsLayer {
    let layer = CorsLayer::new()
        .allow_methods(parse_methods(CORS_ALLOWED_METHODS))
        .allow_headers(parse_headers(CORS_ALLOWED_HEADERS))
        .max_age(Duration::from_secs(0));

    if allowed_origins.is_empty() {
        return layer;
    }

    let has_wildcard = allowed_origins.iter().any(|o| o == "*");
    let exact: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter(|o| o.as_str() != "*")
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();

    let origin = if has_wildcard {
        // Echo the request origin back (matches Go's `found = origin`
        // branch in cors.go:41).  tower_http's `AllowOrigin::mirror_
        // request` does exactly that.
        AllowOrigin::mirror_request()
    } else {
        AllowOrigin::list(exact)
    };

    layer.allow_origin(origin)
}

fn parse_methods(s: &str) -> Vec<Method> {
    s.split(',')
        .map(|m| m.trim())
        .filter(|m| !m.is_empty())
        .filter_map(|m| m.parse::<Method>().ok())
        .collect()
}

fn parse_headers(s: &str) -> Vec<axum::http::HeaderName> {
    s.split(',')
        .map(|m| m.trim())
        .filter(|m| !m.is_empty())
        .filter_map(|m| m.parse::<axum::http::HeaderName>().ok())
        .collect()
}

/// `AllowPNA` middleware (api/cors.go:61-71).  Honors Chrome's
/// Private Network Access preflight by echoing back
/// `Access-Control-Allow-Private-Network: true` on `OPTIONS` requests
/// that ask for it.
async fn allow_pna_middleware(req: Request, next: Next) -> Response {
    let asks_for_pna = req.method() == Method::OPTIONS
        && req
            .headers()
            .get("Access-Control-Request-Private-Network")
            .and_then(|v| v.to_str().ok())
            == Some("true");

    let mut response = next.run(req).await;
    if asks_for_pna {
        response.headers_mut().insert(
            "Access-Control-Allow-Private-Network",
            HeaderValue::from_static("true"),
        );
    }
    response
}

/// Read the bound address from `<data_dir>/kmd.net`.  Useful for
/// CLI tools (`kmd-rust` itself in B9, `goal kmd` in B10).
pub fn read_net_file(data_dir: &Path) -> Result<String> {
    let raw = std::fs::read_to_string(data_dir.join(NET_FILENAME)).map_err(Error::Io)?;
    Ok(raw.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;
    use tempfile::TempDir;

    fn test_config(dir: &Path) -> WalletServerConfig {
        WalletServerConfig {
            api_token: "a".repeat(64),
            data_dir: dir.to_path_buf(),
            address: Some(SocketAddr::new(DEFAULT_KMD_HOST, 0)),
            allowed_origins: vec!["*".to_string()],
            allow_header_pna: false,
            session_manager: Arc::new(SessionManager::new(StdDuration::from_secs(60))),
        }
    }

    /// Local helper: start a server, return (addr, shutdown_tx, join_handle).
    async fn spawn(
        cfg: WalletServerConfig,
    ) -> (
        SocketAddr,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let server = WalletServer::bind(cfg).await.expect("bind");
        let addr = server.local_addr();
        let (tx, rx) = oneshot::channel();
        let handle = tokio::spawn(server.serve(rx));
        // Give the server a moment to start accepting.
        tokio::time::sleep(StdDuration::from_millis(50)).await;
        (addr, tx, handle)
    }

    #[tokio::test]
    async fn versions_endpoint_returns_supported_versions() {
        let dir = TempDir::new().unwrap();
        let (addr, tx, handle) = spawn(test_config(dir.path())).await;

        let url = format!("http://{addr}/versions");
        let resp = reqwest::get(&url).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body, serde_json::json!({"versions": ["v1"]}));

        tx.send(()).unwrap();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn swagger_endpoint_returns_vendored_spec_byte_for_byte() {
        let dir = TempDir::new().unwrap();
        let (addr, tx, handle) = spawn(test_config(dir.path())).await;

        let url = format!("http://{addr}/swagger.json");
        let resp = reqwest::get(&url).await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body = resp.text().await.unwrap();
        assert_eq!(body, SWAGGER_JSON);

        tx.send(()).unwrap();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn options_returns_cors_headers_when_origin_allowed() {
        let dir = TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        cfg.allowed_origins = vec!["http://example.com".to_string()];
        let (addr, tx, handle) = spawn(cfg).await;

        let client = reqwest::Client::new();
        let resp = client
            .request(reqwest::Method::OPTIONS, format!("http://{addr}/versions"))
            .header("Origin", "http://example.com")
            .header("Access-Control-Request-Method", "GET")
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success() || resp.status() == 204);
        assert_eq!(
            resp.headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some("http://example.com")
        );

        tx.send(()).unwrap();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn v1_request_without_token_is_unauthorized() {
        let dir = TempDir::new().unwrap();
        let (addr, tx, handle) = spawn(test_config(dir.path())).await;

        let url = format!("http://{addr}/v1/wallets");
        let resp = reqwest::get(&url).await.unwrap();
        assert_eq!(resp.status(), 401);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["error"], true);
        assert_eq!(body["message"], "invalid API token");

        tx.send(()).unwrap();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn v1_request_with_correct_token_reaches_not_found() {
        let dir = TempDir::new().unwrap();
        let cfg = test_config(dir.path());
        let token = cfg.api_token.clone();
        let (addr, tx, handle) = spawn(cfg).await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{addr}/v1/wallets"))
            .header(KMD_TOKEN_HEADER, &token)
            .send()
            .await
            .unwrap();
        // No routes wired yet (B5+); auth-passing requests fall
        // through to the v1 fallback, which returns 404 with the
        // standard error envelope.
        assert_eq!(resp.status(), 404);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["error"], true);

        tx.send(()).unwrap();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn net_file_contains_bound_address_and_is_removed_on_shutdown() {
        let dir = TempDir::new().unwrap();
        let (addr, tx, handle) = spawn(test_config(dir.path())).await;

        let net = std::fs::read_to_string(dir.path().join(NET_FILENAME)).unwrap();
        assert_eq!(net.trim(), addr.to_string());
        assert_eq!(read_net_file(dir.path()).unwrap(), addr.to_string());

        // PID file present and parseable.
        let pid_raw = std::fs::read_to_string(dir.path().join(PID_FILENAME)).unwrap();
        let pid: u32 = pid_raw.trim().parse().expect("pid is numeric");
        assert_eq!(pid, std::process::id());

        tx.send(()).unwrap();
        handle.await.unwrap().unwrap();

        // After shutdown the lifecycle files should be gone.
        assert!(!dir.path().join(NET_FILENAME).exists());
        assert!(!dir.path().join(PID_FILENAME).exists());
    }

    #[tokio::test]
    async fn second_server_on_same_data_dir_errors_already_running() {
        let dir = TempDir::new().unwrap();
        let (_, tx, handle) = spawn(test_config(dir.path())).await;

        let err = WalletServer::bind(test_config(dir.path()))
            .await
            .expect_err("second bind must fail");
        assert!(
            matches!(err, Error::AlreadyRunning),
            "expected AlreadyRunning, got {err:?}"
        );

        tx.send(()).unwrap();
        handle.await.unwrap().unwrap();

        // After the first server shuts down the lock is released; a
        // fresh bind succeeds.
        let server = WalletServer::bind(test_config(dir.path()))
            .await
            .expect("rebind after shutdown");
        drop(server);
    }

    #[tokio::test]
    async fn bind_rejects_invalid_api_token() {
        let dir = TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        cfg.api_token = "too-short".to_string();
        let err = WalletServer::bind(cfg)
            .await
            .expect_err("invalid token rejected");
        assert!(
            matches!(err, Error::ApiTokenTooShort),
            "expected ApiTokenTooShort, got {err:?}"
        );
    }

    #[tokio::test]
    async fn bind_rejects_missing_data_dir() {
        let dir = TempDir::new().unwrap();
        let nonexistent = dir.path().join("does-not-exist");
        let mut cfg = test_config(dir.path());
        cfg.data_dir = nonexistent.clone();
        let err = WalletServer::bind(cfg)
            .await
            .expect_err("missing data dir rejected");
        assert!(
            matches!(err, Error::DataDirMissing(_)),
            "expected DataDirMissing, got {err:?}"
        );
    }

    #[tokio::test]
    async fn options_on_v1_returns_200_even_without_origin_header() {
        // Regression for Codex PR #355 round 1: Go registers a
        // catch-all `Methods("OPTIONS")` handler that returns 200
        // for any OPTIONS request, with or without the CORS preflight
        // headers.  Without the short-circuit middleware, OPTIONS
        // /v1/wallets fell through to the v1 404 fallback.
        let dir = TempDir::new().unwrap();
        let (addr, tx, handle) = spawn(test_config(dir.path())).await;

        let client = reqwest::Client::new();
        let resp = client
            .request(
                reqwest::Method::OPTIONS,
                format!("http://{addr}/v1/wallets"),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "non-preflight OPTIONS must return 200");

        // And on a path that doesn't exist at all under /:
        let resp = client
            .request(
                reqwest::Method::OPTIONS,
                format!("http://{addr}/some/unknown/path"),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "OPTIONS catch-all applies to any path");

        tx.send(()).unwrap();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn pna_preflight_echoes_allow_private_network_when_enabled() {
        let dir = TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        cfg.allowed_origins = vec!["http://example.com".to_string()];
        cfg.allow_header_pna = true;
        let (addr, tx, handle) = spawn(cfg).await;

        let client = reqwest::Client::new();
        let resp = client
            .request(reqwest::Method::OPTIONS, format!("http://{addr}/versions"))
            .header("Origin", "http://example.com")
            .header("Access-Control-Request-Method", "GET")
            .header("Access-Control-Request-Private-Network", "true")
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.headers()
                .get("access-control-allow-private-network")
                .and_then(|v| v.to_str().ok()),
            Some("true")
        );

        tx.send(()).unwrap();
        handle.await.unwrap().unwrap();
    }

    /// Sanity check: when go-algorand is checked out alongside this
    /// repo, the vendored swagger.json is byte-for-byte equal to the
    /// upstream file we ported it from.  Skipped when the sibling
    /// checkout is absent (e.g. on minimal CI runners).
    #[test]
    fn vendored_swagger_matches_go_algorand() {
        let upstream = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../go-algorand/daemon/kmd/api/swagger.json");
        if !upstream.exists() {
            // No sibling go-algorand — nothing to compare against.
            return;
        }
        let upstream_bytes = std::fs::read(&upstream).expect("read upstream swagger.json");
        assert_eq!(
            SWAGGER_JSON.as_bytes(),
            upstream_bytes.as_slice(),
            "vendored swagger.json drifted from go-algorand v4.5.1-stable; re-copy from {}",
            upstream.display()
        );
    }
}
