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

//! HTTP server wrapper for the Algorand REST API.
//!
//! Provides `ApiServer` which binds to a TCP address and serves the API
//! router until shutdown is signaled. On startup, it writes `algod.net`
//! and reads or generates `algod.token` and `algod.admin.token` in the
//! data directory, matching go-algorand's behavior.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::auth;
use crate::node::NodeInterface;
use crate::router::{self, TokenConfig};

/// Write a token to a file with restrictive permissions (0o600 on Unix).
///
/// On Unix systems, the file is created with mode `0o600` (owner read/write
/// only) to prevent other users from reading the API token. On non-Unix
/// platforms, this falls back to `std::fs::write` with default permissions.
fn write_token_file(path: &Path, token: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(token.as_bytes())?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, token)
    }
}

/// Emits the AGPL section 13 startup log banner, recording where the
/// corresponding source is available for operators running the binary
/// directly -- HTTP clients get the equivalent pointer via the
/// `X-Algod-Rust-Source` response header (see `crate::source_header`).
///
/// Factored out of [`ApiServer::serve`] as a standalone function so it can
/// be unit tested (see the `tests` module below) without needing a full
/// `NodeInterface` implementation and a bound listener.
fn log_source_banner() {
    tracing::info!(
        source = crate::source_header::SOURCE_URL,
        "algod-rust is free software licensed under the AGPLv3 -- corresponding source is available at the URL above"
    );
}

/// Name of the file containing the bound listen address.
const NET_FILE: &str = "algod.net";

/// Name of the file containing the public API token.
const TOKEN_FILE: &str = "algod.token";

/// Name of the file containing the admin API token.
const ADMIN_TOKEN_FILE: &str = "algod.admin.token";

/// Configuration for the API server.
#[derive(Debug, Clone)]
pub struct ApiServerConfig {
    /// The socket address to bind to (e.g. `127.0.0.1:8080`).
    pub listen_addr: SocketAddr,

    /// Path to the node's data directory where token files are stored.
    /// If `None`, token files are not read/written and random tokens are used.
    pub data_dir: Option<PathBuf>,

    /// Override for the public API token. If `None`, the token is read from
    /// `algod.token` in the data directory (or generated if it doesn't exist).
    pub api_token: Option<String>,

    /// Override for the admin API token. If `None`, the token is read from
    /// `algod.admin.token` in the data directory (or generated if it doesn't exist).
    pub admin_token: Option<String>,

    /// Turns off authentication for public (non-admin) API endpoints.
    /// Mirrors go-algorand's `config.Local.DisableAPIAuth` (issue #748).
    /// Callers should default this to `false` (auth enabled), matching
    /// go's default, when no `config.json` override is present.
    pub disable_api_auth: bool,
}

/// The REST API HTTP server.
///
/// Wraps an axum server with the full Algorand REST API router.
pub struct ApiServer {
    config: ApiServerConfig,
}

impl ApiServer {
    /// Create a new API server with the given configuration.
    pub fn new(config: ApiServerConfig) -> Self {
        Self { config }
    }

    /// Resolve the public API token.
    ///
    /// Priority: config override > file on disk > generate new token.
    fn resolve_token(
        data_dir: Option<&Path>,
        override_token: Option<&str>,
        filename: &str,
    ) -> std::io::Result<String> {
        // 1. Use override if provided
        if let Some(token) = override_token {
            return Ok(token.to_string());
        }

        // 2. Try to read from file
        if let Some(dir) = data_dir {
            let path = dir.join(filename);
            match std::fs::read_to_string(&path) {
                Ok(contents) => {
                    let token = contents.trim().to_string();
                    if !token.is_empty() {
                        tracing::info!(file = %path.display(), "loaded API token from file");
                        return Ok(token);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // File doesn't exist, will generate below
                }
                Err(e) => {
                    tracing::warn!(
                        file = %path.display(),
                        err = %e,
                        "failed to read token file, generating new token"
                    );
                }
            }

            // 3. Generate new token and write to file
            let token = auth::generate_token();
            if let Err(e) = write_token_file(&path, &token) {
                tracing::warn!(
                    file = %path.display(),
                    err = %e,
                    "failed to write generated token file"
                );
            } else {
                tracing::info!(file = %path.display(), "generated new API token file");
            }
            return Ok(token);
        }

        // No data dir and no override -- generate an ephemeral token
        Ok(auth::generate_token())
    }

    /// Write the `algod.net` file containing the bound address.
    fn write_net_file(data_dir: &Path, addr: SocketAddr) {
        let path = data_dir.join(NET_FILE);
        if let Err(e) = std::fs::write(&path, addr.to_string()) {
            tracing::warn!(
                file = %path.display(),
                err = %e,
                "failed to write algod.net file"
            );
        } else {
            tracing::info!(file = %path.display(), addr = %addr, "wrote algod.net");
        }
    }

    /// Start serving HTTP requests.
    ///
    /// This method:
    /// 1. Resolves API tokens (from config, files, or generates new ones)
    /// 2. Builds the router with authentication middleware
    /// 3. Binds to the configured address
    /// 4. Writes `algod.net` to the data directory (if configured)
    /// 5. Spawns the server task and returns immediately
    ///
    /// Returns the actual bound address (useful when binding to port 0)
    /// and a `JoinHandle` that completes when the server shuts down.
    /// Callers can await the handle to detect server failures or wait
    /// for graceful shutdown to finish.
    pub async fn serve<N: NodeInterface>(
        &self,
        node: Arc<N>,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(SocketAddr, JoinHandle<()>), std::io::Error> {
        // Resolve tokens
        let api_token = Self::resolve_token(
            self.config.data_dir.as_deref(),
            self.config.api_token.as_deref(),
            TOKEN_FILE,
        )?;
        let admin_token = Self::resolve_token(
            self.config.data_dir.as_deref(),
            self.config.admin_token.as_deref(),
            ADMIN_TOKEN_FILE,
        )?;

        let tokens = TokenConfig {
            api_token,
            admin_token,
            enable_experimental_api: node.enable_experimental_api(),
            disable_api_auth: self.config.disable_api_auth,
        };

        let router = router::build_router(node, tokens);
        let listener = TcpListener::bind(self.config.listen_addr).await?;
        let local_addr = listener.local_addr()?;

        // Write algod.net file
        if let Some(ref data_dir) = self.config.data_dir {
            Self::write_net_file(data_dir, local_addr);
        }

        tracing::info!(addr = %local_addr, "REST API server listening");
        log_source_banner();

        let handle = tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router)
                .with_graceful_shutdown(shutdown)
                .await
            {
                tracing::error!(err = %e, "REST API server failed");
            }
        });

        Ok((local_addr, handle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    /// A `MakeWriter` that appends every write into a shared in-memory
    /// buffer, so a test can assert on the exact rendered log line without
    /// depending on this repo's real (JSON/env-filter) tracing setup.
    #[derive(Clone, Default)]
    struct BufferWriter(Arc<Mutex<Vec<u8>>>);

    impl io::Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for BufferWriter {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Verifies the AGPL section 13 startup banner ([`log_source_banner`])
    /// actually emits a log line naming the exact source repository URL --
    /// the "Startup log banner verified" acceptance criterion from issue
    /// #742.
    #[test]
    fn startup_banner_logs_the_exact_source_url() {
        let buffer = BufferWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, log_source_banner);

        let logged = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert!(
            logged.contains(crate::source_header::SOURCE_URL),
            "startup banner must log the exact source repository URL, got: {logged:?}"
        );
        assert!(
            logged.contains("AGPLv3"),
            "startup banner should mention the AGPLv3 license, got: {logged:?}"
        );
    }
}
