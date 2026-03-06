use std::time::Duration;

use algo_codec::decode_block_response;
use algo_error::{AlgoError, Result};
use algo_types::{BlockResponse, Round};
use async_trait::async_trait;
use tracing::{debug, warn};

use crate::{AccountInfo, BlockSource, NodeStatus};

/// Configuration for the REST client.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Request timeout for normal requests (default: 30s).
    pub timeout: Duration,
    /// Request timeout for long-poll requests like wait_for_round (default: 5min).
    pub long_poll_timeout: Duration,
    /// Maximum number of retry attempts (default: 3).
    pub max_retries: u32,
    /// Initial backoff duration, doubled each retry (default: 100ms).
    pub initial_backoff: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            long_poll_timeout: Duration::from_secs(300),
            max_retries: 3,
            initial_backoff: Duration::from_millis(100),
        }
    }
}

/// REST API client for a go-algorand node.
pub struct AlgodClient {
    base_url: String,
    token: String,
    http: reqwest::Client,
    long_poll_http: reqwest::Client,
    config: ClientConfig,
}

impl AlgodClient {
    /// Create a new client with default configuration.
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Self {
        Self::with_config(base_url, token, ClientConfig::default())
    }

    /// Create a new client with custom configuration.
    pub fn with_config(
        base_url: impl Into<String>,
        token: impl Into<String>,
        config: ClientConfig,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("failed to build HTTP client");

        let long_poll_http = reqwest::Client::builder()
            .timeout(config.long_poll_timeout)
            .build()
            .expect("failed to build long-poll HTTP client");

        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.into(),
            http,
            long_poll_http,
            config,
        }
    }

    /// Execute a GET request with retry and exponential backoff.
    ///
    /// Retries on connection errors, timeouts, and 5xx responses.
    /// Does not retry on 4xx responses.
    async fn get_with_retry(
        &self,
        path: &str,
        client: &reqwest::Client,
    ) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        let mut backoff = self.config.initial_backoff;

        for attempt in 0..=self.config.max_retries {
            let mut request = client.get(&url);

            // Only add the API token header if the token is not empty
            if !self.token.is_empty() {
                request = request.header("X-Algo-API-Token", &self.token);
            }

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
                            "server error, retrying"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff *= 2;
                        continue;
                    }
                    // 4xx or exhausted retries on 5xx — return the error response
                    let body = resp.text().await.unwrap_or_default();
                    if status == reqwest::StatusCode::NOT_FOUND {
                        return Err(AlgoError::NotFound(format!("GET {path}: {body}")));
                    }
                    return Err(AlgoError::Conformance {
                        message: format!("GET {path} returned {status}: {body}"),
                    });
                }
                Err(e) if is_retryable(&e) && attempt < self.config.max_retries => {
                    warn!(
                        attempt = attempt + 1,
                        max = self.config.max_retries,
                        error = %e,
                        path,
                        backoff_ms = backoff.as_millis() as u64,
                        "transient error, retrying"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                }
                Err(e) => {
                    return Err(AlgoError::RestClient {
                        source: Box::new(e),
                        context: format!("GET {path}"),
                    });
                }
            }
        }

        unreachable!("retry loop should always return")
    }
}

impl AlgodClient {
    /// Fetch account information for the given address at the latest round.
    pub async fn get_account(&self, addr: &algo_types::Address) -> algo_error::Result<AccountInfo> {
        let path = format!("/v2/accounts/{}", addr.to_algorand_string());
        let resp = self.get_with_retry(&path, &self.http).await?;
        resp.json::<AccountInfo>()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: format!("parsing account info for {}", addr.to_algorand_string()),
            })
    }

    /// Fetch account information for the given address at a specific round.
    ///
    /// Requires the node to have historical data for the requested round
    /// (i.e., an archival node or a node that hasn't pruned that round yet).
    pub async fn get_account_at_round(
        &self,
        addr: &algo_types::Address,
        round: u64,
    ) -> algo_error::Result<AccountInfo> {
        let path = format!("/v2/accounts/{}?round={}", addr.to_algorand_string(), round);
        let resp = self.get_with_retry(&path, &self.http).await?;
        resp.json::<AccountInfo>()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: format!(
                    "parsing account info for {} at round {}",
                    addr.to_algorand_string(),
                    round
                ),
            })
    }
}

/// Check if a reqwest error is transient and worth retrying.
fn is_retryable(err: &reqwest::Error) -> bool {
    err.is_connect() || err.is_timeout() || err.is_request()
}

#[async_trait]
impl BlockSource for AlgodClient {
    async fn get_block_raw(&self, round: Round) -> Result<Vec<u8>> {
        debug!(round = %round, "fetching block (msgpack)");

        let path = format!("/v2/blocks/{}?format=msgpack", round);
        let resp = self.get_with_retry(&path, &self.http).await?;

        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: format!("reading body for block {round}"),
            })
    }

    async fn get_block(&self, round: Round) -> Result<BlockResponse> {
        let bytes = self.get_block_raw(round).await?;
        decode_block_response(&bytes)
    }

    async fn get_status(&self) -> Result<NodeStatus> {
        debug!("fetching node status");

        let resp = self.get_with_retry("/v2/status", &self.http).await?;

        resp.json::<NodeStatus>()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: "parsing /v2/status response".into(),
            })
    }

    async fn wait_for_round(&self, round: Round) -> Result<NodeStatus> {
        debug!(round = %round, "waiting for round");

        let path = format!("/v2/status/wait-for-block-after/{}", round);
        let resp = self.get_with_retry(&path, &self.long_poll_http).await?;

        resp.json::<NodeStatus>()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: format!("parsing wait-for-block-after/{round} response"),
            })
    }
}
