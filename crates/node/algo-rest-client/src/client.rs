use std::time::Duration;

use algo_codec::decode_block_response;
use algo_error::{AlgoError, Result};
use algo_types::{BlockResponse, Round};
use async_trait::async_trait;
use tracing::{debug, warn};

use crate::{
    AccountInfo, BlockSource, NodeStatus, PendingTxnInfo, PostTransactionResponse, SuggestedParams,
    TxId,
};

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

    /// Execute a POST request with retry and exponential backoff.
    ///
    /// Mirrors `get_with_retry`: retries on connection errors, timeouts, and
    /// 5xx responses; does not retry on 4xx (those propagate as
    /// [`AlgoError::NotFound`] for 404 or [`AlgoError::Conformance`] otherwise).
    async fn post_with_retry(
        &self,
        path: &str,
        content_type: &'static str,
        body: Vec<u8>,
    ) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        let mut backoff = self.config.initial_backoff;

        for attempt in 0..=self.config.max_retries {
            let mut request = self
                .http
                .post(&url)
                .header(reqwest::header::CONTENT_TYPE, content_type)
                .body(body.clone());

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
                    let body_text = resp.text().await.unwrap_or_default();
                    if status == reqwest::StatusCode::NOT_FOUND {
                        return Err(AlgoError::NotFound(format!("POST {path}: {body_text}")));
                    }
                    return Err(AlgoError::Conformance {
                        message: format!("POST {path} returned {status}: {body_text}"),
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
                        context: format!("POST {path}"),
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

impl AlgodClient {
    /// Submit a single msgpack-encoded `SignedTxn` (or transaction group) to the
    /// node via `POST /v2/transactions`. Returns the txid the node assigns to
    /// (the first transaction of) the group.
    ///
    /// The node validates the txn against the current consensus protocol and
    /// adds it to the transaction pool synchronously. A 400 response indicates
    /// the pool rejected the transaction (bad signature, insufficient fee,
    /// stale validity window, etc.); a 503 indicates the node is currently
    /// catching up.
    ///
    /// Ported reference: `../go-algorand/daemon/algod/api/server/v2/handlers.go:1090`
    /// (`RawTransaction`). Content-Type is `application/x-binary` per the
    /// algod OpenAPI spec.
    pub async fn send_raw_transaction(&self, raw: &[u8]) -> Result<TxId> {
        debug!(bytes = raw.len(), "submitting raw transaction");

        let resp = self
            .post_with_retry("/v2/transactions", "application/x-binary", raw.to_vec())
            .await?;

        let parsed: PostTransactionResponse =
            resp.json().await.map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: "parsing POST /v2/transactions response".into(),
            })?;

        Ok(TxId(parsed.tx_id))
    }

    /// Look up a transaction by txid in the pool or in recent blocks via
    /// `GET /v2/transactions/pending/{txid}`.
    ///
    /// Distinguishes three states:
    /// - **Committed**: `confirmed_round = Some(round)`, `pool_error = ""`
    /// - **Pending**: `confirmed_round = None`, `pool_error = ""`
    /// - **Rejected**: `pool_error != ""` (rare — usually the txn drops out
    ///   of the pool before this is observable)
    ///
    /// A txid the node has never seen returns `AlgoError::NotFound`; a txid
    /// that has been evicted past `MaxTxnLife` rounds returns the same.
    ///
    /// Ported reference: `../go-algorand/daemon/algod/api/server/v2/handlers.go:1505`
    /// (`PendingTransactionInformation`). We request the default JSON encoding
    /// (`format=json`); the msgpack form carries the same fields.
    pub async fn get_pending_transaction(&self, txid: &TxId) -> Result<PendingTxnInfo> {
        debug!(%txid, "fetching pending transaction");

        let path = format!("/v2/transactions/pending/{}", txid.as_str());
        let resp = self.get_with_retry(&path, &self.http).await?;

        resp.json::<PendingTxnInfo>()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: format!("parsing GET /v2/transactions/pending/{}", txid.as_str()),
            })
    }

    /// Fetch suggested transaction parameters via `GET /v2/transactions/params`.
    ///
    /// The returned `SuggestedParams` carries the genesis hash as a decoded
    /// `Digest` (algod returns it base64-encoded over the wire), and includes
    /// the current consensus version's `min_fee` so callers don't have to look
    /// it up separately.
    ///
    /// Ported reference: `../go-algorand/daemon/algod/api/server/v2/handlers.go:1459`
    /// (`TransactionParams`).
    pub async fn suggested_transaction_params(&self) -> Result<SuggestedParams> {
        debug!("fetching suggested transaction params");

        let resp = self
            .get_with_retry("/v2/transactions/params", &self.http)
            .await?;

        resp.json::<SuggestedParams>()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: "parsing GET /v2/transactions/params response".into(),
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
