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

//! kmd HTTP server bootstrap.
//!
//! Ported from `../go-algorand/daemon/kmd/server/server.go` and
//! `daemon/kmd/api/{api,cors}.go` (v4.6.0-stable). Brings up an axum
//! server on `127.0.0.1:auto`, writes the `kmd.net` / `kmd.pid` /
//! `kmd.lock` lifecycle files, exposes the two non-versioned routes
//! (`GET /versions`, `GET /swagger.json`), handles OPTIONS for CORS,
//! and enforces the bearer-token middleware on every `/v1/*` route.
//!
//! ## Routing (go v5.1.1-stable)
//!
//! go moved the kmd API from gorilla/mux to `http.ServeMux` with a `/`
//! catch-all. [`go_mux`] reproduces what that answers, as proven on the rows
//! of `tests/fixtures/kmd_route_oracle.jsonl`: an unclean path (`//`, `.`, `..`)
//! is redirected (307) to its cleaned form; a request with the wrong method,
//! an unknown path or an unknown `/v1` path is a plain-text 404, whether or
//! not it carries a token (auth applies only to a matched `/v1` route); `HEAD`
//! reaches `GET` routes; `/versions` and `/swagger.json` take any method.
//! Only a matched `/v1` route runs the auth check and then the request
//! callback (the watchdog, `--timeout`).
//!
//! - No TLS — kmd binds localhost only, matching Go.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use fs2::FileExt;
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::api_v1;
use crate::auth::validate_api_token;
use crate::error::{Error, Result};
use crate::session::SessionManager;
use crate::wallet::WalletDriver;

/// `NetFilename` (server.go:40) — file containing `host:port`.
pub const NET_FILENAME: &str = "kmd.net";
/// `PIDFilename` (server.go:42).
pub const PID_FILENAME: &str = "kmd.pid";
/// `LockFilename` (server.go:44).
pub const LOCK_FILENAME: &str = "kmd.lock";
/// The mode gofrs/flock creates `kmd.lock` with (`flock.New`).
const LOCK_FILE_MODE: u32 = 0o600;
/// The mode go's kmd writes `kmd.net` / `kmd.pid` with (server.go:146-151).
const NET_PID_FILE_MODE: u32 = 0o640;

/// `opts.open(path)`, a file it creates getting `mode` (less the umask) on
/// Unix, like go's `os.OpenFile(.., perm)`.
fn open_with_mode(
    opts: &mut std::fs::OpenOptions,
    path: &Path,
    mode: u32,
) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    opts.open(path)
}

/// go's `os.WriteFile(path, data, mode)`: truncate or create (with `mode`).
fn write_file_with_mode(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    open_with_mode(
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true),
        path,
        mode,
    )?
    .write_all(data)
}

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
/// (v4.6.0-stable).  Served byte-for-byte at `GET /swagger.json`.
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
    /// Wallet driver — backs the v1 wallet routes (B5+).
    pub wallet_driver: Arc<WalletDriver>,
    /// go's `Timeout`: kmd shuts itself down once this long has passed
    /// without an authenticated request to a `/v1` route (the watchdog
    /// starts when the server does). `None`: never.
    pub timeout: Option<Duration>,
}

/// go's `reqCB`: called once per request that passed auth on a `/v1` route.
pub type RequestCallback = Arc<dyn Fn() + Send + Sync>;

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

/// `ERROR_LOCK_VIOLATION` — the Win32 code `LockFileEx` returns when the
/// requested region is already locked by another handle. The standard
/// library doesn't map this to `io::ErrorKind::WouldBlock` (unlike Unix's
/// `flock`/`EWOULDBLOCK`), so [`WalletServer::bind`] checks the raw OS error
/// directly to recognize a lock conflict on Windows.
#[cfg(windows)]
const ERROR_LOCK_VIOLATION: i32 = 33;

/// Whether `e` is Windows' lock-conflict error. Always `false` on
/// non-Windows targets, where `WouldBlock` alone is sufficient.
#[cfg(windows)]
fn is_windows_lock_violation(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(ERROR_LOCK_VIOLATION)
}

#[cfg(not(windows))]
fn is_windows_lock_violation(_e: &std::io::Error) -> bool {
    false
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
        // gofrs/flock opens the lock file with mode 0600.
        let lock_file = open_with_mode(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false),
            &lock_path,
            LOCK_FILE_MODE,
        )
        .map_err(Error::Io)?;
        if let Err(e) = lock_file.try_lock_exclusive() {
            // fs2 returns `WouldBlock` on Unix (`flock` maps `EWOULDBLOCK`
            // cleanly) when another process holds the lock; surface that as
            // `AlreadyRunning` so the caller gets the same Go-side
            // `ErrAlreadyRunning` message. On Windows, `LockFileEx`'s
            // conflict error (`ERROR_LOCK_VIOLATION`, raw code 33) isn't
            // mapped to `WouldBlock` by the standard library, so check the
            // raw OS error too.
            if e.kind() == std::io::ErrorKind::WouldBlock || is_windows_lock_violation(&e) {
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

        // Write kmd.net + kmd.pid (server.go:143-152), `os.WriteFile(.., 0640)`.
        write_file_with_mode(&net_path, addr.to_string().as_bytes(), NET_PID_FILE_MODE)
            .map_err(Error::Io)?;
        write_file_with_mode(
            &pid_path,
            std::process::id().to_string().as_bytes(),
            NET_PID_FILE_MODE,
        )
        .map_err(Error::Io)?;

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
        self.router_with_callback(Arc::new(|| {}))
    }

    /// [`router`](Self::router) with go's request callback (`reqCB`).
    pub fn router_with_callback(&self, request_cb: RequestCallback) -> Router {
        build_router(
            self.config.api_token.clone(),
            self.config.allowed_origins.clone(),
            self.config.allow_header_pna,
            api_v1::AppState {
                session_manager: self.config.session_manager.clone(),
                wallet_driver: self.config.wallet_driver.clone(),
            },
            request_cb,
        )
    }

    /// Serve forever, until `shutdown` resolves.  On any exit
    /// (graceful or panic), `kmd.net` and `kmd.pid` are removed and
    /// the file lock is released.  Matches the back half of
    /// `start` (server.go:267-290).
    pub async fn serve(self, shutdown: oneshot::Receiver<()>) -> Result<()> {
        // go's `makeWatchdogCallback`: with a timeout, kmd is killed when no
        // request has called the callback for that long.
        let (request_cb, watchdog) = match self.config.timeout {
            Some(timeout) => {
                let (cb, expired) = make_watchdog(timeout);
                (cb, Some(expired))
            }
            None => (Arc::new(|| {}) as RequestCallback, None),
        };
        let router = self.router_with_callback(request_cb);
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
                match watchdog {
                    Some(expired) => tokio::select! {
                        _ = shutdown => {}
                        () = expired => tracing::info!("killing kmd after timeout"),
                    },
                    None => {
                        let _ = shutdown.await;
                    }
                }
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

/// go's `makeWatchdogCallback`: the callback to run per request, and a
/// future that resolves once `timeout` has passed without one.
fn make_watchdog(timeout: Duration) -> (RequestCallback, impl std::future::Future<Output = ()>) {
    use std::sync::atomic::{AtomicU64, Ordering};
    let epoch = Instant::now();
    let last_ms = Arc::new(AtomicU64::new(0));
    let cb_last = last_ms.clone();
    let cb: RequestCallback = Arc::new(move || {
        cb_last.store(epoch.elapsed().as_millis() as u64, Ordering::SeqCst);
    });
    let expired = async move {
        loop {
            let deadline = epoch + Duration::from_millis(last_ms.load(Ordering::SeqCst)) + timeout;
            tokio::time::sleep_until(deadline.into()).await;
            // a request may have reset the timer while this slept
            let now = Instant::now();
            if now >= epoch + Duration::from_millis(last_ms.load(Ordering::SeqCst)) + timeout {
                return;
            }
        }
    };
    (cb, expired)
}

/// The routes [`go_mux`] hands on: go's `RegisterHandlers` (`api/v1/handlers.go`).
struct GoMux {
    /// The `/v1` handlers behind the auth check and the request callback.
    v1: Router,
}

/// Every `/v1` route of `RegisterHandlers`: `(method, path below /v1)`.
const V1_ROUTES: &[(&str, &str)] = &[
    ("GET", "/wallets"),
    ("POST", "/wallet"),
    ("POST", "/wallet/init"),
    ("POST", "/wallet/release"),
    ("POST", "/wallet/renew"),
    ("POST", "/wallet/rename"),
    ("POST", "/wallet/info"),
    ("POST", "/master-key/export"),
    ("POST", "/key/list"),
    ("POST", "/key/import"),
    ("POST", "/key/export"),
    ("POST", "/key"),
    ("DELETE", "/key"),
    ("POST", "/multisig/list"),
    ("POST", "/multisig/sign"),
    ("POST", "/multisig/signprogram"),
    ("POST", "/multisig/import"),
    ("POST", "/multisig/export"),
    ("DELETE", "/multisig"),
    ("POST", "/transaction/sign"),
    ("POST", "/program/sign"),
];

/// Build the root router.  Exposed so tests can drive it with
/// `tower::Service` without binding a real socket.
///
/// The layers are go's `Handler`: PNA outermost (when enabled), then CORS,
/// then the OPTIONS short-circuit, then the mux.
fn build_router(
    api_token: String,
    allowed_origins: Vec<String>,
    allow_header_pna: bool,
    state: api_v1::AppState,
    request_cb: RequestCallback,
) -> Router {
    let auth_state = AuthState {
        expected_token: Arc::new(api_token),
    };

    // `/v1/*`: auth first, then the request callback, then the handler
    // (`auth(cb(handler))`, `RegisterHandlers`).  Axum: the last `.layer` is
    // outermost.
    let v1 = api_v1::router(state)
        .layer(axum::middleware::from_fn_with_state(
            request_cb,
            request_callback_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            auth_state,
            require_kmd_token,
        ));

    let mux = Arc::new(GoMux { v1 });
    let mut app = Router::new().fallback(any(go_mux)).with_state(mux);

    // Every OPTIONS request — preflight or not — short-circuits to 200 before
    // routing (`optionsMiddleware`), and the CORS middleware that ran on the
    // way in stamps its headers on the way out.  Axum layer semantics: the most
    // recently added `.layer(...)` is outermost.
    app = app.layer(axum::middleware::from_fn(options_short_circuit));

    app = app.layer(axum::middleware::from_fn_with_state(
        Arc::new(allowed_origins),
        cors_middleware,
    ));

    if allow_header_pna {
        app = app.layer(axum::middleware::from_fn(allow_pna_middleware));
    }

    app
}

/// go's `reqCallbackMiddleware`: runs the callback once per request that
/// reaches it (after auth).
async fn request_callback_middleware(
    State(cb): State<RequestCallback>,
    req: Request,
    next: Next,
) -> Response {
    cb();
    next.run(req).await
}

/// go's `path.Clean` on a slash-rooted path.
fn path_clean(p: &str) -> String {
    let rooted = p.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if !out.is_empty() {
                    out.pop();
                } else if !rooted {
                    out.push("..");
                }
            }
            s => out.push(s),
        }
    }
    let joined = out.join("/");
    if rooted {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

/// `http.ServeMux`'s `cleanPath`.
fn mux_clean_path(p: &str) -> String {
    if p.is_empty() {
        return "/".to_string();
    }
    let p = if p.starts_with('/') {
        p.to_string()
    } else {
        format!("/{p}")
    };
    let np = path_clean(&p);
    // path.Clean removes the trailing slash except for the root; put it back
    if p.ends_with('/') && np != "/" {
        if p.len() == np.len() + 1 && p.starts_with(&np) {
            return p;
        }
        return format!("{np}/");
    }
    np
}

/// go's `pathUnescape`: `url.PathUnescape`, the input itself when it is not
/// validly escaped.
fn path_unescape(seg: &str) -> Vec<u8> {
    let b = seg.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = |c: u8| (c as char).to_digit(16);
            match (b.get(i + 1).copied().and_then(hex), b.get(i + 2).copied().and_then(hex)) {
                (Some(h), Some(l)) => {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                }
                _ => return b.to_vec(),
            }
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

/// What `http.Redirect(w, r, location, 307)` writes: a `Location`, and for GET
/// and HEAD an HTML content type with, for GET, a short body.
fn redirect_response(method: &Method, location: &str) -> Response {
    let mut builder = Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header(header::LOCATION, location);
    if method == Method::GET || method == Method::HEAD {
        builder = builder.header(header::CONTENT_TYPE, "text/html; charset=utf-8");
    }
    let body = if method == Method::GET {
        let escaped = location
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&#34;")
            .replace('\'', "&#39;");
        format!("<a href=\"{escaped}\">Temporary Redirect</a>.\n\n")
    } else {
        String::new()
    };
    builder
        .body(axum::body::Body::from(body))
        .expect("static redirect response")
}

/// `http.NotFoundHandler`.
fn mux_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        "404 page not found\n",
    )
        .into_response()
}

/// `http.ServeMux` over go's kmd routes (`api.Handler`): see the module docs.
/// The path is the escaped one the request carried; a request URI go's
/// `net/http` would reject as unparsable (an invalid `%` escape) never reaches
/// a go handler, and is not told apart here.
async fn go_mux(State(mux): State<Arc<GoMux>>, req: Request) -> Response {
    use tower::ServiceExt;

    let method = req.method().clone();
    let escaped = req.uri().path().to_string();
    let query = req.uri().query().map(str::to_owned);

    // "All other requests have any port stripped and path cleaned": CONNECT is
    // not canonicalized.
    let path = if method == Method::CONNECT {
        escaped.clone()
    } else {
        mux_clean_path(&escaped)
    };
    if path != escaped {
        let location = match &query {
            Some(q) if !q.is_empty() => format!("{path}?{q}"),
            _ => path,
        };
        return redirect_response(&method, &location);
    }

    // Match: segments are compared unescaped; a trailing slash is an extra empty
    // segment, which no pattern but the `/` catch-all takes.
    let segments: Vec<Vec<u8>> = path
        .strip_prefix('/')
        .unwrap_or(&path)
        .split('/')
        .map(path_unescape)
        .collect();
    let seg = |i: usize| segments.get(i).map(|s| s.as_slice());

    // `/versions` and `/swagger.json` name no method: any is served.
    if segments.len() == 1 {
        if seg(0) == Some(b"versions") {
            return versions_handler().await;
        }
        if seg(0) == Some(b"swagger.json") {
            return swagger_handler().await;
        }
    }
    if seg(0) == Some(b"v1") && segments.len() > 1 {
        // `GET` patterns also match `HEAD`
        let pattern_method = if method == Method::HEAD {
            "GET"
        } else {
            method.as_str()
        };
        let below: Vec<&[u8]> = segments[1..].iter().map(|s| s.as_slice()).collect();
        for (m, route) in V1_ROUTES {
            let parts: Vec<&[u8]> = route
                .trim_start_matches('/')
                .split('/')
                .map(str::as_bytes)
                .collect();
            if *m == pattern_method && parts == below {
                let mut parts = req.into_parts();
                let mut uri = (*route).to_string();
                if let Some(q) = &query {
                    uri.push('?');
                    uri.push_str(q);
                }
                parts.0.uri = uri.parse().expect("route path is a valid URI");
                let req = Request::from_parts(parts.0, parts.1);
                return mux
                    .v1
                    .clone()
                    .oneshot(req)
                    .await
                    .expect("axum routers are infallible");
            }
        }
    }
    mux_not_found()
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
/// `{"versions": ["v1"]}` (indented).  No auth.
async fn versions_handler() -> Response {
    // go writes `protocol.EncodeJSON(response)`: indented by two spaces, no
    // trailing newline.
    let versions: Vec<String> = SUPPORTED_API_VERSIONS
        .iter()
        .map(|v| format!("    {}", serde_json::to_string(v).expect("a string serializes")))
        .collect();
    let body = format!(
        "{{\n  \"versions\": [\n{}\n  ]\n}}",
        versions.join(",\n")
    );
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body,
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
        api_v1::encode_json(&body),
    )
        .into_response()
}

/// go's `corsMiddleware` (api/cors.go): each allowed origin is compared with
/// the request's `Origin` in constant time; an entry of `"*"` echoes whatever
/// `Origin` the client sent (nothing if it sent none). Only when one matched
/// are the three `Access-Control-Allow-*` headers set, on whatever the request
/// goes on to produce (`TestCORS`: a 404 carries them too); the request is
/// served regardless, since the client may not be a browser.
async fn cors_middleware(
    State(allowed_origins): State<Arc<Vec<String>>>,
    req: Request,
    next: Next,
) -> Response {
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .map(|v| v.as_bytes().to_vec())
        .unwrap_or_default();
    let mut found: Option<Vec<u8>> = None;
    for allowed in allowed_origins.iter() {
        if origin.as_slice().ct_eq(allowed.as_bytes()).into() {
            found = Some(allowed.as_bytes().to_vec());
            break;
        } else if allowed == "*" {
            found = Some(origin.clone());
            break;
        }
    }

    let mut response = next.run(req).await;
    if let Some(found) = found.filter(|f| !f.is_empty()) {
        if let Ok(value) = HeaderValue::from_bytes(&found) {
            let headers = response.headers_mut();
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static(CORS_ALLOWED_HEADERS),
            );
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static(CORS_ALLOWED_METHODS),
            );
        }
    }
    response
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
        use crate::config::ScryptParams;
        use crate::wallet::{WalletDriver, WalletDriverConfig};
        // Spin up a real WalletDriver pointed at a wallets/ subdir of
        // the data dir.  Unsafe scrypt for fast tests.
        let wallets_dir = dir.join("wallets");
        std::fs::create_dir_all(&wallets_dir).unwrap();
        let driver = WalletDriver::new(WalletDriverConfig {
            wallets_dir,
            scrypt_params: ScryptParams {
                scrypt_n: 2,
                scrypt_r: 1,
                scrypt_p: 1,
            },
            allow_unsafe_scrypt: true,
        })
        .unwrap();
        WalletServerConfig {
            api_token: "a".repeat(64),
            data_dir: dir.to_path_buf(),
            address: Some(SocketAddr::new(DEFAULT_KMD_HOST, 0)),
            allowed_origins: vec!["*".to_string()],
            allow_header_pna: false,
            session_manager: Arc::new(SessionManager::new(StdDuration::from_secs(60))),
            wallet_driver: Arc::new(driver),
            timeout: None,
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
    async fn v1_request_with_correct_token_reaches_unknown_route() {
        let dir = TempDir::new().unwrap();
        let cfg = test_config(dir.path());
        let token = cfg.api_token.clone();
        let (addr, tx, handle) = spawn(cfg).await;

        let client = reqwest::Client::new();
        // A path that isn't a real v1 route is the mux's plain-text 404, with
        // or without a token (go v5.1.1 `http.ServeMux` + `/` catch-all).
        let resp = client
            .get(format!("http://{addr}/v1/no-such-route"))
            .header(KMD_TOKEN_HEADER, &token)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
        assert_eq!(resp.text().await.unwrap(), "404 page not found\n");

        // The real `/v1/wallets` route now serves 200 with an empty
        // (or omitted) `wallets` field once authenticated.
        let resp = client
            .get(format!("http://{addr}/v1/wallets"))
            .header(KMD_TOKEN_HEADER, &token)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(body.get("wallets").is_none() || body["wallets"].as_array().unwrap().is_empty());

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

    const ROUTE_ORACLE: &str = include_str!("../tests/fixtures/kmd_route_oracle.jsonl");

    /// A router over a fresh wallet driver, with go's `Handler` arguments.
    fn oracle_router(
        driver: &Arc<WalletDriver>,
        origins: Vec<String>,
        pna: bool,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Router {
        build_router(
            "a".repeat(64),
            origins,
            pna,
            api_v1::AppState {
                session_manager: Arc::new(SessionManager::new(StdDuration::from_secs(60))),
                wallet_driver: driver.clone(),
            },
            Arc::new(move || {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }),
        )
    }

    fn oracle_driver(dir: &Path) -> Arc<WalletDriver> {
        use crate::config::ScryptParams;
        use crate::wallet::{WalletDriver, WalletDriverConfig};
        Arc::new(
            WalletDriver::new(WalletDriverConfig {
                wallets_dir: dir.to_path_buf(),
                scrypt_params: ScryptParams {
                    scrypt_n: 2,
                    scrypt_r: 1,
                    scrypt_p: 1,
                },
                allow_unsafe_scrypt: true,
            })
            .unwrap(),
        )
    }

    /// go-generated rows (`tools/kmd-route-oracle`, go v5.1.1-stable
    /// `api.Handler`): status, the headers that matter, the body and the
    /// request-callback count of every method x path x token x CORS setup. Go's
    /// `ServeMux` rows include the redirects of unclean paths, the plain-text
    /// 404s (wrong method, unknown path, unknown `/v1` path, with or without a
    /// token) and `HEAD` reaching `GET` routes.
    #[tokio::test]
    async fn kmd_routing_matches_go_on_every_oracle_row() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tower::ServiceExt;

        const HEADERS: [&str; 8] = [
            "content-type",
            "location",
            "x-content-type-options",
            "allow",
            "access-control-allow-origin",
            "access-control-allow-headers",
            "access-control-allow-methods",
            "access-control-allow-private-network",
        ];
        let dir = TempDir::new().unwrap();
        let driver = oracle_driver(dir.path());
        let mut rows = 0;
        for line in ROUTE_ORACLE.lines() {
            let row: serde_json::Value = serde_json::from_str(line).unwrap();
            let origins: Vec<String> = row["origins"]
                .as_array()
                .map(|a| a.iter().map(|o| o.as_str().unwrap().to_string()).collect())
                .unwrap_or_default();
            let pna = row["pna"].as_bool().unwrap();
            let method = row["method"].as_str().unwrap();
            let path = row["path"].as_str().unwrap();
            let what = format!(
                "{} {method} {path} token={} (go row)",
                row["setup"], row["token"]
            );

            let calls = Arc::new(AtomicUsize::new(0));
            let router = oracle_router(&driver, origins, pna, calls.clone());
            let mut req = Request::builder()
                .method(method)
                .uri(path)
                .body(axum::body::Body::from(row["body"].as_str().unwrap().to_string()))
                .unwrap();
            match row["token"].as_str().unwrap() {
                "ok" => {
                    req.headers_mut()
                        .insert(KMD_TOKEN_HEADER, "a".repeat(64).parse().unwrap());
                }
                "bad" => {
                    req.headers_mut()
                        .insert(KMD_TOKEN_HEADER, "b".repeat(64).parse().unwrap());
                }
                _ => {}
            }
            if let Some(origin) = row["origin"].as_str().filter(|o| !o.is_empty()) {
                req.headers_mut().insert("origin", origin.parse().unwrap());
            }
            // go sends it on every request: only a preflight with PNA enabled answers it
            req.headers_mut().insert(
                "access-control-request-private-network",
                "true".parse().unwrap(),
            );

            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(
                resp.status().as_u16() as u64,
                row["status"].as_u64().unwrap(),
                "{what}: status"
            );
            let want_headers = row["headers"].as_object().unwrap();
            for name in HEADERS {
                let got = resp.headers().get(name).map(|v| v.to_str().unwrap().to_string());
                let want = want_headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v.as_str().unwrap().to_string());
                assert_eq!(got, want, "{what}: header {name}");
            }
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            // a real server drops the body of a HEAD answer; go's recorder does not
            if method != "HEAD" {
                assert_eq!(
                    String::from_utf8_lossy(&bytes),
                    row["response"].as_str().unwrap(),
                    "{what}: body"
                );
            }
            assert_eq!(
                calls.load(Ordering::SeqCst) as u64,
                row["cb_calls"].as_u64().unwrap(),
                "{what}: request callback calls"
            );
            rows += 1;
        }
        assert!(rows > 2000, "only {rows} oracle rows");
    }

    /// go `TestRequestCallback` / `TestRequestCallbackNotCalledWithoutAuth`:
    /// the callback runs once per authenticated v1 request that reaches a
    /// route, and never for one the auth check rejects.
    #[tokio::test]
    async fn request_callback_runs_only_after_auth() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tower::ServiceExt;

        let dir = TempDir::new().unwrap();
        let driver = oracle_driver(dir.path());
        let calls = Arc::new(AtomicUsize::new(0));
        let router = oracle_router(&driver, vec![], false, calls.clone());

        let authed = Request::builder()
            .method("POST")
            .uri("/v1/wallet/info")
            .header(KMD_TOKEN_HEADER, "a".repeat(64))
            .body(axum::body::Body::from("{bad json"))
            .unwrap();
        let resp = router.clone().oneshot(authed).await.unwrap();
        assert_eq!(resp.status(), 400);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let unauthed = Request::builder()
            .method("GET")
            .uri("/v1/wallets")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.oneshot(unauthed).await.unwrap();
        assert_eq!(resp.status(), 401);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "auth rejected: no callback");
    }

    /// go `makeWatchdogCallback`: with a timeout kmd stops itself once no
    /// request has called the callback for that long; a request resets it.
    #[tokio::test]
    async fn watchdog_stops_the_server_after_the_timeout_and_requests_reset_it() {
        let dir = TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        cfg.timeout = Some(StdDuration::from_millis(900));
        let token = cfg.api_token.clone();
        let server = WalletServer::bind(cfg).await.expect("bind");
        let addr = server.local_addr();
        let (_tx, rx) = oneshot::channel::<()>();
        let mut handle = tokio::spawn(server.serve(rx));

        let client = reqwest::Client::new();
        let authed = |path: &str| {
            client
                .post(format!("http://{addr}{path}"))
                .header(KMD_TOKEN_HEADER, &token)
                .body("{bad json")
                .send()
        };
        // a request at 500 ms resets the 900 ms timer ...
        tokio::time::sleep(StdDuration::from_millis(500)).await;
        assert_eq!(authed("/v1/wallet/info").await.unwrap().status(), 400);
        // ... so the server still answers at 1200 ms (> 900 ms after the start)
        tokio::time::sleep(StdDuration::from_millis(700)).await;
        assert!(!handle.is_finished(), "stopped although a request reset the timer");
        assert_eq!(authed("/v1/wallet/info").await.unwrap().status(), 400);
        // ... and, with no request left, it stops by itself
        let stopped = tokio::time::timeout(StdDuration::from_secs(5), &mut handle).await;
        assert!(stopped.is_ok(), "the watchdog never stopped the server");
        assert!(!dir.path().join(NET_FILENAME).exists());
    }

    /// Every v1 route: go's `allV1Endpoints` (`api/v1/handlers_test.go`).
    const ALL_V1_ENDPOINTS: [(&str, &str); 21] = [
        ("GET", "/v1/wallets"),
        ("POST", "/v1/wallet"),
        ("POST", "/v1/wallet/init"),
        ("POST", "/v1/wallet/release"),
        ("POST", "/v1/wallet/renew"),
        ("POST", "/v1/wallet/rename"),
        ("POST", "/v1/wallet/info"),
        ("POST", "/v1/master-key/export"),
        ("POST", "/v1/key/list"),
        ("POST", "/v1/key/import"),
        ("POST", "/v1/key/export"),
        ("POST", "/v1/key"),
        ("DELETE", "/v1/key"),
        ("POST", "/v1/multisig/list"),
        ("POST", "/v1/multisig/sign"),
        ("POST", "/v1/multisig/signprogram"),
        ("POST", "/v1/multisig/import"),
        ("POST", "/v1/multisig/export"),
        ("DELETE", "/v1/multisig"),
        ("POST", "/v1/transaction/sign"),
        ("POST", "/v1/program/sign"),
    ];

    /// What one request to the full router (auth included) answered.
    struct Answer {
        status: u16,
        content_type: Option<String>,
        body: String,
    }

    async fn call(router: &Router, method: &str, path: &str, token: Option<&str>, body: &str) -> Answer {
        use tower::ServiceExt;
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        if let Some(t) = token {
            req.headers_mut()
                .insert(KMD_TOKEN_HEADER, t.parse().unwrap());
        }
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap().to_string());
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        Answer {
            status,
            content_type,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    fn json_of(a: &Answer) -> serde_json::Value {
        serde_json::from_str(&a.body).unwrap_or_else(|e| panic!("not JSON ({e}): {}", a.body))
    }

    /// go `TestAuthRejectsNoToken`, `TestAuthRejectsWrongToken` and
    /// `TestErrorResponseContentType`: every v1 route answers 401 JSON without
    /// the token or with a wrong one.
    #[tokio::test]
    async fn every_v1_route_rejects_a_missing_or_wrong_token() {
        let dir = TempDir::new().unwrap();
        let router = oracle_router(
            &oracle_driver(dir.path()),
            vec![],
            false,
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        );
        let wrong = "b".repeat(64);
        for (method, path) in ALL_V1_ENDPOINTS {
            for token in [None, Some(wrong.as_str())] {
                let a = call(&router, method, path, token, "").await;
                assert_eq!(a.status, 401, "{method} {path} token {token:?}");
                assert_eq!(a.content_type.as_deref(), Some("application/json"));
                assert_eq!(json_of(&a)["error"], true);
            }
        }
    }

    /// go `TestAuthAcceptsValidToken`, `TestMalformedJSONBody` and
    /// `TestEmptyRequestBody`: with the token every route gets past auth and,
    /// for a malformed or empty body, answers 400 "could not decode ...".
    #[tokio::test]
    async fn every_v1_route_with_the_token_rejects_a_malformed_or_empty_body() {
        let dir = TempDir::new().unwrap();
        let router = oracle_router(
            &oracle_driver(dir.path()),
            vec![],
            false,
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        );
        let token = "a".repeat(64);
        for (method, path) in ALL_V1_ENDPOINTS {
            // GET /v1/wallets reads no body and lists the wallets
            if method == "GET" {
                continue;
            }
            for body in ["{bad json", ""] {
                let a = call(&router, method, path, Some(&token), body).await;
                assert_eq!(a.status, 400, "{method} {path} body {body:?}: {}", a.body);
                let v = json_of(&a);
                assert_eq!(v["error"], true);
                assert!(
                    v["message"].as_str().unwrap().contains("could not decode"),
                    "{method} {path}: {}",
                    a.body
                );
            }
        }
    }

    /// go `TestWalletInfoHandler`, `TestWalletRenewHandler`,
    /// `TestWalletReleaseHandler`, `TestInvalidHandleToken` and
    /// `TestResponseContentType`, through the full router with a token.
    #[tokio::test]
    async fn wallet_handle_info_renew_release_and_invalid_token() {
        let dir = TempDir::new().unwrap();
        let router = oracle_router(
            &oracle_driver(dir.path()),
            vec![],
            false,
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        );
        let token = "a".repeat(64);
        let created = call(
            &router,
            "POST",
            "/v1/wallet",
            Some(&token),
            r#"{"wallet_name":"test-wallet","wallet_driver_name":"sqlite","wallet_password":"pw"}"#,
        )
        .await;
        assert_eq!(created.status, 200, "{}", created.body);
        let wallet_id = json_of(&created)["wallet"]["id"].as_str().unwrap().to_string();
        let init = call(
            &router,
            "POST",
            "/v1/wallet/init",
            Some(&token),
            &format!(r#"{{"wallet_id":"{wallet_id}","wallet_password":"pw"}}"#),
        )
        .await;
        assert_eq!(init.status, 200, "{}", init.body);
        let handle = json_of(&init)["wallet_handle_token"].as_str().unwrap().to_string();
        let req = format!(r#"{{"wallet_handle_token":"{handle}"}}"#);

        let info = call(&router, "POST", "/v1/wallet/info", Some(&token), &req).await;
        assert_eq!(info.status, 200, "{}", info.body);
        assert_eq!(info.content_type.as_deref(), Some("application/json"));
        let v = json_of(&info);
        assert!(v.get("error").is_none() || v["error"] == false);
        assert_eq!(v["wallet_handle"]["wallet"]["id"], wallet_id.as_str());
        assert_eq!(v["wallet_handle"]["wallet"]["name"], "test-wallet");
        assert!(v["wallet_handle"]["expires_seconds"].as_i64().unwrap() > 0);

        let renew = call(&router, "POST", "/v1/wallet/renew", Some(&token), &req).await;
        assert_eq!(renew.status, 200, "{}", renew.body);
        let v = json_of(&renew);
        assert_eq!(v["wallet_handle"]["wallet"]["name"], "test-wallet");
        assert!(v["wallet_handle"]["expires_seconds"].as_i64().unwrap() > 0);

        let release = call(&router, "POST", "/v1/wallet/release", Some(&token), &req).await;
        assert_eq!(release.status, 200, "{}", release.body);
        // the released handle no longer works
        let after = call(&router, "POST", "/v1/wallet/info", Some(&token), &req).await;
        assert_eq!(after.status, 401, "{}", after.body);

        // a handle that never existed
        let bogus = call(
            &router,
            "POST",
            "/v1/wallet/info",
            Some(&token),
            r#"{"wallet_handle_token":"bogus-token"}"#,
        )
        .await;
        assert_eq!(bogus.status, 401);
        assert_eq!(json_of(&bogus)["error"], true);
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
        // Normalize CRLF -> LF on both sides before comparing: this checks
        // for *content* drift against the sibling go-algorand checkout, and
        // that checkout's own line endings depend on how it was cloned
        // (e.g. Windows with `core.autocrlf=true`) — not something this
        // repo's `.gitattributes` controls. Content drift is what matters;
        // a `\n` vs `\r\n` difference from the reference clone's local
        // checkout config is not a real divergence.
        let normalize = |b: &[u8]| -> Vec<u8> {
            String::from_utf8_lossy(b)
                .replace("\r\n", "\n")
                .into_bytes()
        };
        assert_eq!(
            normalize(SWAGGER_JSON.as_bytes()),
            normalize(&upstream_bytes),
            "vendored swagger.json drifted from go-algorand v4.6.0-stable; re-copy from {}",
            upstream.display()
        );
    }
}
