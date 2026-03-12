use std::path::Path;
use std::time::Duration;

use algo_error::{AlgoError, Result};
use tracing::{debug, info, warn};

/// Default chunk size for streaming reads (64 KiB).
const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// Progress information reported during a catchpoint file download.
#[derive(Debug, Clone)]
pub struct DownloadProgress {
    /// Number of bytes downloaded so far.
    pub bytes_downloaded: u64,
    /// Total expected bytes from the `Content-Length` header, if available.
    pub total_bytes: Option<u64>,
}

/// Configuration for catchpoint file downloads.
#[derive(Debug, Clone)]
pub struct CatchpointDownloadConfig {
    /// Overall request timeout (default: 30 minutes — catchpoint files can be 500MB+).
    pub timeout: Duration,
    /// Read buffer size hint in bytes (default: 64 KiB).
    ///
    /// Note: the actual chunk sizes returned by `reqwest` may differ from this
    /// value. This is used as a guidance for progress reporting frequency.
    pub chunk_size: usize,
    /// Maximum number of retry attempts on transient errors (default: 3).
    pub max_retries: u32,
    /// Delay between retries, doubled on each successive retry (default: 1s).
    pub retry_delay: Duration,
}

impl Default for CatchpointDownloadConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30 * 60),
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
        }
    }
}

/// Streaming HTTP client for downloading catchpoint (ledger) files from an
/// Algorand node.
///
/// The Go endpoint serves catchpoint data at
/// `GET /v1/{genesisID}/ledger/{round}` where `round` is **base-36 encoded**.
///
/// See `go-algorand/rpcs/ledgerService.go` for the server implementation.
pub struct CatchpointDownloader {
    base_url: String,
    token: String,
    http: reqwest::Client,
    config: CatchpointDownloadConfig,
}

impl CatchpointDownloader {
    /// Create a new downloader with the default configuration.
    pub fn new(base_url: &str, token: &str) -> Self {
        Self::with_config(base_url, token, CatchpointDownloadConfig::default())
    }

    /// Create a new downloader with a custom configuration.
    pub fn with_config(base_url: &str, token: &str, config: CatchpointDownloadConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("failed to build HTTP client for catchpoint downloads");

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            http,
            config,
        }
    }

    /// Download a catchpoint file to `dest_path`.
    ///
    /// The file is first written to a temporary sibling file in the same
    /// directory, then atomically renamed to `dest_path` on success.  This
    /// ensures that a partially-downloaded file never appears at the final
    /// path.
    ///
    /// The `progress_cb` callback, if provided, is invoked periodically with
    /// the current download progress (at most once per `chunk_size` bytes of
    /// data received).
    ///
    /// # Arguments
    ///
    /// * `genesis_id` — e.g. `"mainnet-v1.0"`
    /// * `round` — the catchpoint round to download
    /// * `dest_path` — final destination path for the downloaded file
    /// * `progress_cb` — optional progress callback
    pub async fn download<F>(
        &self,
        genesis_id: &str,
        round: u64,
        dest_path: &Path,
        progress_cb: Option<F>,
    ) -> Result<()>
    where
        F: Fn(DownloadProgress),
    {
        // Encode the round in base 36, matching the Go server's expectation.
        let round_b36 = radix_fmt(round, 36);
        let path = format!("/v1/{genesis_id}/ledger/{round_b36}");

        debug!(round, %round_b36, genesis_id, "starting catchpoint download");

        let response = self.get_with_retry(&path).await?;

        // Extract total size from Content-Length if the server provides it.
        let total_bytes = response.content_length();

        if let Some(total) = total_bytes {
            info!(
                round,
                total_bytes = total,
                "catchpoint download: content-length known"
            );
        }

        // Ensure the parent directory exists.
        if let Some(parent) = dest_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                AlgoError::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "failed to create parent directory {}: {e}",
                        parent.display()
                    ),
                ))
            })?;
        }

        // Write to a temp file alongside the destination, then rename.
        let tmp_path = dest_path.with_extension("tmp");

        let result = self
            .stream_to_file(response, &tmp_path, total_bytes, &progress_cb)
            .await;

        match result {
            Ok(()) => {
                tokio::fs::rename(&tmp_path, dest_path).await.map_err(|e| {
                    AlgoError::Io(std::io::Error::new(
                        e.kind(),
                        format!(
                            "failed to rename {} -> {}: {e}",
                            tmp_path.display(),
                            dest_path.display()
                        ),
                    ))
                })?;
                info!(round, path = %dest_path.display(), "catchpoint download complete");
                Ok(())
            }
            Err(e) => {
                // Best-effort cleanup of the temp file.
                let _ = tokio::fs::remove_file(&tmp_path).await;
                Err(e)
            }
        }
    }

    /// Stream a response body to a file on disk, invoking `progress_cb`
    /// after each chunk.
    async fn stream_to_file<F>(
        &self,
        mut response: reqwest::Response,
        path: &Path,
        total_bytes: Option<u64>,
        progress_cb: &Option<F>,
    ) -> Result<()>
    where
        F: Fn(DownloadProgress),
    {
        use tokio::io::AsyncWriteExt;

        let mut file = tokio::fs::File::create(path).await.map_err(|e| {
            AlgoError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to create temp file {}: {e}", path.display()),
            ))
        })?;

        let mut bytes_downloaded: u64 = 0;
        let mut bytes_since_progress: usize = 0;

        // Use reqwest's chunk() method to stream the response body without
        // buffering the entire payload in memory.
        while let Some(chunk) = response.chunk().await.map_err(|e| AlgoError::RestClient {
            source: Box::new(e),
            context: format!(
                "reading chunk at offset {bytes_downloaded} from {}",
                path.display()
            ),
        })? {
            file.write_all(&chunk).await.map_err(|e| {
                AlgoError::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "failed to write {} bytes at offset {bytes_downloaded} to {}: {e}",
                        chunk.len(),
                        path.display()
                    ),
                ))
            })?;

            bytes_downloaded += chunk.len() as u64;
            bytes_since_progress += chunk.len();

            // Report progress at most once per `chunk_size` bytes to avoid
            // excessive callback overhead with very small HTTP chunks.
            if bytes_since_progress >= self.config.chunk_size {
                bytes_since_progress = 0;
                if let Some(ref cb) = progress_cb {
                    cb(DownloadProgress {
                        bytes_downloaded,
                        total_bytes,
                    });
                }
            }
        }

        file.flush().await.map_err(|e| {
            AlgoError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to flush {}: {e}", path.display()),
            ))
        })?;

        // Final progress report.
        if let Some(ref cb) = progress_cb {
            cb(DownloadProgress {
                bytes_downloaded,
                total_bytes,
            });
        }

        debug!(
            bytes_downloaded,
            "catchpoint file written to {}",
            path.display()
        );
        Ok(())
    }

    /// Execute a GET request with retry and exponential backoff.
    ///
    /// Follows the same pattern as `AlgodClient::get_with_retry`.
    async fn get_with_retry(&self, path: &str) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        let mut backoff = self.config.retry_delay;

        for attempt in 0..=self.config.max_retries {
            let mut request = self.http.get(&url);

            // Send the auth token the same way AlgodClient does.
            if !self.token.is_empty() {
                request = request.header("X-Algo-API-Token", &self.token);
            }

            // Request gzip-compressed transfer to reduce bandwidth, matching
            // the Go client behaviour.
            request = request.header("Accept-Encoding", "gzip");

            let result = request.send().await;

            match result {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return Ok(resp);
                    }
                    if status.is_server_error() && attempt < self.config.max_retries {
                        warn!(
                            attempt = attempt + 1,
                            max = self.config.max_retries,
                            status = %status,
                            path,
                            backoff_ms = backoff.as_millis() as u64,
                            "catchpoint download: server error, retrying"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff *= 2;
                        continue;
                    }
                    // 4xx or exhausted retries on 5xx.
                    let body = resp.text().await.unwrap_or_default();
                    if status == reqwest::StatusCode::NOT_FOUND {
                        return Err(AlgoError::NotFound(format!(
                            "catchpoint GET {path}: {body}"
                        )));
                    }
                    return Err(AlgoError::RestClient {
                        source: Box::new(std::io::Error::other(format!("HTTP {status}"))),
                        context: format!("catchpoint GET {path}: {body}"),
                    });
                }
                Err(e) if is_retryable(&e) && attempt < self.config.max_retries => {
                    warn!(
                        attempt = attempt + 1,
                        max = self.config.max_retries,
                        error = %e,
                        path,
                        backoff_ms = backoff.as_millis() as u64,
                        "catchpoint download: transient error, retrying"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                }
                Err(e) => {
                    return Err(AlgoError::RestClient {
                        source: Box::new(e),
                        context: format!("catchpoint GET {path}"),
                    });
                }
            }
        }

        unreachable!("retry loop should always return")
    }
}

/// Check if a reqwest error is transient and worth retrying.
fn is_retryable(err: &reqwest::Error) -> bool {
    err.is_connect() || err.is_timeout()
}

/// Format a `u64` as a base-36 string (digits 0-9, then a-z).
///
/// Go's `strconv.ParseUint(s, 36, 64)` accepts lowercase letters, so we
/// produce lowercase output.
fn radix_fmt(mut value: u64, radix: u32) -> String {
    if value == 0 {
        return "0".to_string();
    }
    let radix = radix as u64;
    let mut digits = Vec::new();
    while value > 0 {
        let d = (value % radix) as u8;
        let ch = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
        digits.push(ch as char);
        value /= radix;
    }
    digits.reverse();
    digits.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_radix_fmt_base36() {
        // 0
        assert_eq!(radix_fmt(0, 36), "0");
        // 1..35 → single digit
        assert_eq!(radix_fmt(10, 36), "a");
        assert_eq!(radix_fmt(35, 36), "z");
        // 36 → "10"
        assert_eq!(radix_fmt(36, 36), "10");
        // Known value: Go's strconv.FormatUint(1000000, 36) == "lfls"
        assert_eq!(radix_fmt(1_000_000, 36), "lfls");
        // Larger: Go's strconv.FormatUint(12345678, 36) == "7clzi"
        assert_eq!(radix_fmt(12_345_678, 36), "7clzi");
    }

    #[test]
    fn test_default_config() {
        let config = CatchpointDownloadConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(30 * 60));
        assert_eq!(config.chunk_size, DEFAULT_CHUNK_SIZE);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay, Duration::from_secs(1));
    }

    #[test]
    fn test_constructor_trims_trailing_slash() {
        let dl = CatchpointDownloader::new("http://localhost:4001/", "mytoken");
        assert_eq!(dl.base_url, "http://localhost:4001");
    }

    #[test]
    fn test_constructor_no_trailing_slash() {
        let dl = CatchpointDownloader::new("http://localhost:4001", "mytoken");
        assert_eq!(dl.base_url, "http://localhost:4001");
    }
}
